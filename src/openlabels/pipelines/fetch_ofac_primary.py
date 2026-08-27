#!/usr/bin/env python3
"""Fetch crypto wallet addresses straight from OFAC — the primary publisher.

WHY THIS EXISTS
---------------
Aggregators such as OpenSanctions redistribute OFAC data under CC-BY-NC 4.0,
which restricts commercial use of the aggregate. Measured 2026-08-03: the
entire OpenSanctions catalogue (461 datasets, 4,335,704 entities) carried
exactly 12,917 crypto wallets, coming from just 7 child datasets — each with
a public primary source. OFAC is the largest of them.

A work of the US Government is not subject to copyright (17 U.S.C. 105), so
fetching straight from OFAC carries no licence condition in any scenario —
open weights, closed weights, commercial or not. The value of this path is
licence, provenance and freshness.

OUTPUT
------
`ofac_wallets.json`   one row per (address, currency) with entity name, OFAC
                      entity id and the designation programs
`manifest.json`       counts + sha256 of the source XML and of the output

The designation programs are carried through deliberately: OFAC's own taxonomy
(CYBER2 / SDGT / DPRK4 / FTO / ILLICIT-DRUGS-EO14059 …) is the cleanest
family label available.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

SOURCES = {
    "sdn_enhanced": "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN_ENHANCED.XML",
    "cons_enhanced": "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/CONS_ENHANCED.XML",
}
PREFIX = "Digital Currency Address - "


def _tag(el: ET.Element) -> str:
    return el.tag.rsplit("}", 1)[-1]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    """curl, not urllib: the OFAC endpoint rejects the default python UA."""
    r = subprocess.run(
        ["curl", "-sSL", "--fail", "--max-time", "300", "-o", str(dest), url],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"download failed {url}: rc={r.returncode} {r.stderr.strip()}")
    if dest.stat().st_size < 100_000:
        raise RuntimeError(f"{dest.name} is {dest.stat().st_size} B — truncated or an error page")


def parse(path: Path) -> list[dict]:
    """Entity-scoped extraction.

    Layout verified against the live file rather than assumed — note that
    featureTypeId sits on the <type> CHILD, not on <feature>:

        <entity id="4632">
          <sanctionsPrograms><sanctionsProgram>IRAN</sanctionsProgram>…
          <names>…<translation><formattedFullName>BANK MARKAZI …
          <features>
            <feature id="97667">
              <type featureTypeId="992">Digital Currency Address - TRX</type>
              <value>TNiq9AXBp9EjUqhDhrwrfvAA8U3GUQZH81</value>
    """
    rows: list[dict] = []
    for _, ent in ET.iterparse(str(path), events=("end",)):
        if _tag(ent) != "entity":
            continue
        feats = []
        for f in ent.iter():
            if _tag(f) != "feature":
                continue
            ftype = next(((c.text or "").strip() for c in f if _tag(c) == "type"), "")
            if not ftype.startswith(PREFIX):
                continue
            val = next((c.text.strip() for c in f
                        if _tag(c) == "value" and (c.text or "").strip()), None)
            if val:
                feats.append((ftype[len(PREFIX):].strip(), val))
        if feats:
            name = next((n.text.strip() for n in ent.iter()
                         if _tag(n) == "formattedFullName" and (n.text or "").strip()), None)
            programs = sorted({p.text.strip() for p in ent.iter()
                               if _tag(p) == "sanctionsProgram" and (p.text or "").strip()})
            for currency, address in feats:
                rows.append({"address": address, "currency": currency,
                             "entity_name": name, "entity_id": ent.get("id"),
                             "programs": programs})
        ent.clear()
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, type=Path, help="output directory")
    ap.add_argument("--keep-xml", action="store_true", help="retain the downloaded XML")
    ap.add_argument("--min-addresses", type=int, default=800,
                    help="HALT if fewer distinct addresses than this (schema-drift gate)")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    src_meta = {}
    for name, url in SOURCES.items():
        xml = a.out / f"{name}.xml"
        download(url, xml)
        digest = sha256_of(xml)
        part = parse(xml)
        src_meta[name] = {"url": url, "bytes": xml.stat().st_size,
                          "sha256": digest, "crypto_feature_rows": len(part)}
        print(f"{name:<14} {xml.stat().st_size:>12,} B  sha256 {digest[:16]}…  "
              f"rows {len(part):,}", file=sys.stderr)
        rows += part
        if not a.keep_xml:
            xml.unlink()

    seen, uniq = set(), []
    for r in rows:
        key = (r["address"], r["currency"])
        if key not in seen:
            seen.add(key)
            uniq.append(r)

    addresses = {r["address"] for r in uniq}
    if len(addresses) < a.min_addresses:
        raise SystemExit(
            f"HALT: {len(addresses)} distinct addresses < floor {a.min_addresses}. "
            "OFAC has never shrunk this list; treat as schema drift, not as news."
        )

    out_json = a.out / "ofac_wallets.json"
    out_json.write_text(json.dumps(uniq, indent=1))
    manifest = {
        "generated_utc": subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                                        capture_output=True, text=True).stdout.strip(),
        "publisher": "US Department of the Treasury, Office of Foreign Assets Control",
        "licence": "US Government work — not subject to copyright (17 U.S.C. 105)",
        "sources": src_meta,
        "rows_address_currency": len(uniq),
        "distinct_addresses": len(addresses),
        "by_currency": dict(Counter(r["currency"] for r in uniq).most_common()),
        "by_program": dict(Counter(p for r in uniq for p in r["programs"]).most_common()),
        "entity_names_resolved": sum(1 for r in uniq if r["entity_name"]),
        "output_sha256": sha256_of(out_json),
    }
    (a.out / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(f"\ndistinct addresses      : {len(addresses):,}")
    print(f"(address, currency) rows: {len(uniq):,}")
    print(f"designation programs    : {len(manifest['by_program'])}")
    print(f"entity names resolved   : {manifest['entity_names_resolved']:,}/{len(uniq):,}")
    print(f"written {out_json} + manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
