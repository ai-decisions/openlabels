"""Build vasp_to_address — direct exchange-label match (confidence 1.0).

- Layer 1.0 (direct label match) ONLY in this builder.
- Lower-confidence layers (cluster expansion) are deliberately out of scope:
  every row here is a direct label match, nothing inferred.

Inputs:
  data/vasp_directory_v2.json      (canonical VASP entities, multi-jurisdiction)
  unified label store JSON         (addresses with exchange labels)

Output (mode --build):
  data/vasp_to_address_v1.parquet  one row per (vasp_canonical_id, address)
  data/vasp_to_address_v1.manifest.json

Default quality gates:
  - >=1,000 mapped records (any direct-label confidence)
  - >=40 multi-jurisdiction entities with >=1 labelled address each

Mode --profile: coverage matrix only, no parquet write. Used to surface
data-gap analysis to user BEFORE committing to a full build.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

# Reuse the canonical name normalization + alias maps from merge_vasp_directory
# so that label names and directory names go through identical canonicalization.
from openlabels.registry.merge_vasp_directory import (
    ENTITY_ALIASES,
    EXACT_NAME_TO_ALIAS,
    is_junk_name,
    normalize_name,
)

# Strip suffixes that exchange labels use: "Coinbase 14", "Binance: Hot Wallet",
# "Coinbase: Deposit Funder", "Kraken: Hot Wallet", "Kraken-Cold", "HTX-Cold".
LABEL_SUFFIX_RE = re.compile(
    r"(?:\s*[:\-]\s*[a-z0-9\s]+|\s+\d+|\s*\([^)]+\))*$",
    re.IGNORECASE,
)


def label_to_brand(label_name: str) -> str:
    """Extract brand from a unified-labels exchange name.

    Examples:
        'Coinbase 14'            -> 'coinbase'
        'Binance: Hot Wallet'    -> 'binance'
        'Coinbase: Deposit Funder' -> 'coinbase'
        'Kraken-Cold'            -> 'kraken'
        'HTX-Cold'               -> 'htx'
        'binance-hot'            -> 'binance'
    """
    if not label_name:
        return ""
    s = label_name.strip().lower()
    # Strip ': suffix' / '- suffix' / ' N' / ' (foo)' iteratively until stable
    for _ in range(5):
        new = re.sub(r"\s*[:\-]\s*[a-z0-9].*$", "", s)
        new = re.sub(r"\s+\d+$", "", new)
        new = re.sub(r"\s*\([^)]+\)$", "", new)
        if new == s:
            break
        s = new
    return s.strip()


# Label-only alias overrides — apply ONLY in this builder (NOT to merge_vasp_directory).
# The directory pipeline uses ENTITY_ALIASES from
# merge_vasp_directory; we add label-side substrings here to capture brands that
# appear with punctuation in label sources (Etherscan / Dune Spellbook) but were
# not anticipated by the directory-side alias rules. These additions never
# change canonical_id values — they only widen the label→canonical match.
LABEL_EXTRA_ALIASES: list[tuple[str, str]] = [
    ("gate.io", "gate_io"),       # Spellbook writes "Gate.io" (period); directory alias is "gate " trailing-space
    ("gate.com", "gate_io"),      # historical alt-domain
    ("circle internet", "circle"),  # already in ENTITY_ALIASES, listed for clarity
    ("paypal", "paypal"),         # ensure PayPal labels (if added in future) bind to alias::paypal
    ("blockchain.com", "blockchain_com"),  # period variant
]


def label_to_canonical(label_name: str) -> str | None:
    """Map a unified-labels exchange label to a directory canonical_id.

    Mirrors `merge_vasp_directory.canonical_id` priority chain:
      1. exact-name match in EXACT_NAME_TO_ALIAS
      2. junk-guard reject
      3. substring match in ENTITY_ALIASES (first match wins)
      4. substring match in LABEL_EXTRA_ALIASES (label-side punctuation variants)
      5. None (no canonical mapping; address dropped on direct-only path)

    LEI-pinned aliases (LEI_TO_ALIAS) do not apply here — labels never
    carry LEIs.
    """
    if not label_name:
        return None

    brand = label_to_brand(label_name)
    if not brand:
        return None

    # Junk-guard: reject obvious scam-templated names before alias matching
    if is_junk_name(brand):
        return None

    # Exact-name override
    if brand in EXACT_NAME_TO_ALIAS:
        return f"alias::{EXACT_NAME_TO_ALIAS[brand]}"

    # Substring match (order matters)
    for needle, canonical in ENTITY_ALIASES:
        if needle in brand:
            return f"alias::{canonical}"

    # Label-only extras (punctuation variants)
    for needle, canonical in LABEL_EXTRA_ALIASES:
        if needle in brand:
            return f"alias::{canonical}"

    # No alias hit. Fall through to normalized-name fallback so that an
    # exchange-typed label that is not in our directory (e.g. small CEX)
    # still produces a canonical-id key — but only if the normalized name
    # is non-empty.
    norm = normalize_name(brand)
    if norm:
        return f"name::{norm}"
    return None


def load_directory(path: Path) -> list[dict]:
    """Load vasp_directory_v2.json — top-level is a list of canonical entities."""
    with path.open() as f:
        data = json.load(f)
    if isinstance(data, dict) and "entities" in data:
        return data["entities"]
    if isinstance(data, list):
        return data
    raise ValueError(f"unexpected directory shape: {type(data)}")


def load_labels(path: Path) -> dict[str, dict]:
    """Load a unified label store JSON — top-level dict {address: record}."""
    with path.open() as f:
        return json.load(f)


def build_label_index(labels: dict[str, dict]) -> dict[str, list[dict]]:
    """Reverse-index: canonical_id -> list of {address, chain, raw_label_names}.

    Aggregates ALL exchange-typed labels per address (one address can carry
    multiple Etherscan labels). If any of them maps to a canonical, the
    address attaches to that canonical. If multiple canonicals match, the
    first label-order wins (deterministic; matches Etherscan list order).
    """
    index: dict[str, list[dict]] = defaultdict(list)
    label_unmapped = Counter()
    label_total_exchange = 0
    label_address_dropped = 0

    for addr, rec in labels.items():
        chain = rec.get("chain", "unknown")
        exchange_labels = [
            lbl for lbl in rec.get("labels", [])
            if (lbl.get("type") or "").lower() == "exchange"
        ]
        if not exchange_labels:
            continue
        label_total_exchange += 1

        canonical_for_addr: str | None = None
        raw_names: list[str] = []
        for lbl in exchange_labels:
            name = lbl.get("name", "")
            raw_names.append(name)
            if canonical_for_addr is None:
                hit = label_to_canonical(name)
                if hit is not None:
                    canonical_for_addr = hit

        if canonical_for_addr is None:
            label_address_dropped += 1
            for n in raw_names:
                brand = label_to_brand(n)
                label_unmapped[brand or "(empty)"] += 1
            continue

        index[canonical_for_addr].append({
            "address": addr,
            "chain": chain,
            "raw_label_names": raw_names,
        })

    return {
        "index": dict(index),
        "stats": {
            "exchange_addresses_total": label_total_exchange,
            "exchange_addresses_mapped": label_total_exchange - label_address_dropped,
            "exchange_addresses_unmapped": label_address_dropped,
            "top_unmapped_brands": label_unmapped.most_common(40),
        },
    }


def build_vasp_records(
    directory: list[dict],
    label_index: dict[str, list[dict]],
) -> tuple[list[dict], dict]:
    """Cross-join directory entities with label index by canonical_id.

    Returns (records, stats) where records is a flat list of:
        {
            vasp_canonical_id: str,
            vasp_canonical_name: str,
            vasp_n_jurisdictions: int,
            vasp_jurisdictions: list[str],
            address: str,
            chain: str,
            confidence: 1.0,
            match_type: "direct_label",
            raw_label_names: list[str],
        }
    """
    records: list[dict] = []
    entity_addr_count: dict[str, int] = {}
    multijur_with_addresses: list[dict] = []
    multijur_without_addresses: list[dict] = []

    for entity in directory:
        cid = entity.get("canonical_id") or entity.get("id")
        if not cid:
            continue
        cname = entity.get("canonical_name") or entity.get("name") or ""
        licenses = entity.get("licenses", [])
        jurs = sorted(set(lic.get("jurisdiction") for lic in licenses if lic.get("jurisdiction")))
        n_jur = len(jurs)

        addresses = label_index.get(cid, [])
        entity_addr_count[cid] = len(addresses)

        if n_jur >= 2:
            entry = {"canonical_id": cid, "canonical_name": cname, "n_jur": n_jur,
                     "jurisdictions": jurs, "n_addresses": len(addresses)}
            if addresses:
                multijur_with_addresses.append(entry)
            else:
                multijur_without_addresses.append(entry)

        for addr_rec in addresses:
            records.append({
                "vasp_canonical_id": cid,
                "vasp_canonical_name": cname,
                "vasp_n_jurisdictions": n_jur,
                "vasp_jurisdictions": jurs,
                "address": addr_rec["address"],
                "chain": addr_rec["chain"],
                "confidence": 1.0,
                "match_type": "direct_label",
                "raw_label_names": addr_rec["raw_label_names"],
            })

    stats = {
        "n_records": len(records),
        "n_unique_entities_with_addresses": sum(1 for n in entity_addr_count.values() if n > 0),
        "n_unique_entities_total": len(directory),
        "n_multijur_entities_total": len(multijur_with_addresses) + len(multijur_without_addresses),
        "n_multijur_entities_with_addresses": len(multijur_with_addresses),
        "n_multijur_entities_without_addresses": len(multijur_without_addresses),
        "multijur_with_addresses": sorted(multijur_with_addresses, key=lambda x: -x["n_addresses"]),
        "multijur_without_addresses": sorted(multijur_without_addresses, key=lambda x: (-x["n_jur"], x["canonical_name"])),
    }
    return records, stats


def write_parquet(records: list[dict], out_path: Path) -> str:
    """Write records to parquet via pyarrow. Returns sha256 of the file."""
    import hashlib

    import pyarrow as pa
    import pyarrow.parquet as pq

    if not records:
        raise ValueError("no records to write")

    table = pa.Table.from_pylist(records)
    pq.write_table(table, out_path, compression="snappy")

    h = hashlib.sha256()
    with out_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(
    out_path: Path,
    parquet_path: Path,
    parquet_sha: str,
    n_records: int,
    stats: dict,
    label_stats: dict,
    directory_sha: str,
    labels_sha: str,
) -> None:
    manifest = {
        "schema_version": "vasp_to_address_v1",
        "build_utc": datetime.now(UTC).isoformat(),
        "method": "direct-label only, 1.0 confidence",
        "inputs": {
            "vasp_directory_v2.parquet_or_json_sha256": directory_sha,
            "labels_sha256": labels_sha,
        },
        "output": {
            "path": str(parquet_path.name),
            "sha256": parquet_sha,
            "n_records": n_records,
        },
        "quality_floors": {
            "min_records": 1000,
            "min_multijur_entities_with_addresses": 40,
            "stretch_multijur": 50,
        },
        "summary": {
            "n_records": stats["n_records"],
            "n_unique_entities_with_addresses": stats["n_unique_entities_with_addresses"],
            "n_unique_entities_total": stats["n_unique_entities_total"],
            "n_multijur_entities_total": stats["n_multijur_entities_total"],
            "n_multijur_entities_with_addresses": stats["n_multijur_entities_with_addresses"],
            "n_multijur_entities_without_addresses": stats["n_multijur_entities_without_addresses"],
        },
        "schema_notes": {
            "confidence": "1.0 = direct-label match; lower-confidence cluster expansion deliberately excluded",
            "match_type": "direct_label = brand-canonical match between unified_labels exchange-typed label and vasp_directory canonical_id",
            "raw_label_names": "List of original Etherscan-style label strings that produced the match — kept for audit trail",
        },
        "label_index_stats": label_stats,
    }
    with out_path.open("w") as f:
        json.dump(manifest, f, indent=2)


def file_sha256(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_profile(args: argparse.Namespace) -> int:
    """Coverage profile only — no parquet write.

    Surfaces:
      - Total records reachable
      - Multi-jur entities with vs without on-chain labels
      - Top unmapped exchange brands (data-gap signal)
      - Per-multi-jur-entity address count
    """
    t0 = time.time()
    directory = load_directory(Path(args.directory))
    print(f"[load] directory: {len(directory)} canonical entities ({time.time()-t0:.2f}s)")

    t1 = time.time()
    labels = load_labels(Path(args.labels))
    print(f"[load] labels: {len(labels)} addresses ({time.time()-t1:.2f}s)")

    t2 = time.time()
    label_idx = build_label_index(labels)
    n_canon = len(label_idx["index"])
    s = label_idx["stats"]
    print(f"[index] {n_canon} canonical brands extracted from {s['exchange_addresses_total']} exchange-labelled addresses ({time.time()-t2:.2f}s)")
    print(f"[index] mapped {s['exchange_addresses_mapped']}, unmapped {s['exchange_addresses_unmapped']}")

    t3 = time.time()
    records, stats = build_vasp_records(directory, label_idx["index"])
    print(f"[build] {stats['n_records']} records, {stats['n_unique_entities_with_addresses']} entities with addresses ({time.time()-t3:.2f}s)")

    print()
    print("=== quality gates ===")
    rec_pass = stats["n_records"] >= 1000
    mj_pass = stats["n_multijur_entities_with_addresses"] >= 40
    mj_stretch = stats["n_multijur_entities_with_addresses"] >= 50
    print(f"records >=1000:             {stats['n_records']:>6}  {'PASS' if rec_pass else 'FAIL'}")
    print(f"multijur entities >=40:     {stats['n_multijur_entities_with_addresses']:>6}  {'PASS' if mj_pass else 'FAIL'}  (stretch >=50: {'PASS' if mj_stretch else 'FAIL'})")

    print()
    print("=== Multi-jur entities WITH labelled addresses ===")
    for e in stats["multijur_with_addresses"]:
        print(f"  {e['n_addresses']:>4}  {e['n_jur']}-jur  {e['canonical_id']:<40}  {','.join(e['jurisdictions'])}")

    print()
    print(f"=== Multi-jur entities WITHOUT labelled addresses ({stats['n_multijur_entities_without_addresses']}) ===")
    for e in stats["multijur_without_addresses"]:
        print(f"  {e['n_jur']}-jur  {e['canonical_id']:<40}  {','.join(e['jurisdictions'])}")

    print()
    print("=== Top 30 unmapped exchange brands (data gap candidates) ===")
    for brand, cnt in s["top_unmapped_brands"][:30]:
        print(f"  {cnt:>5}  {brand}")

    print()
    print(f"[total wall-time] {time.time()-t0:.2f}s")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    """Full build → parquet + manifest. Use after --profile shows healthy coverage."""
    t0 = time.time()
    directory_path = Path(args.directory)
    labels_path = Path(args.labels)
    out_parquet = Path(args.output)
    out_manifest = out_parquet.with_suffix(".manifest.json")

    directory = load_directory(directory_path)
    labels = load_labels(labels_path)
    print(f"[load] {len(directory)} entities, {len(labels)} addresses")

    label_idx = build_label_index(labels)
    records, stats = build_vasp_records(directory, label_idx["index"])
    print(f"[build] {stats['n_records']} records, {stats['n_unique_entities_with_addresses']} entities with addresses, {stats['n_multijur_entities_with_addresses']} multi-jur with addresses")

    rec_pass = stats["n_records"] >= 1000
    mj_pass = stats["n_multijur_entities_with_addresses"] >= 40
    if not (rec_pass and mj_pass):
        print(f"[FAIL] PASS criteria not met (records={stats['n_records']}>=1000:{rec_pass}, multijur={stats['n_multijur_entities_with_addresses']}>=40:{mj_pass})")
        if not args.allow_partial:
            print("[FAIL] refusing to write output. Re-run with --allow-partial to write anyway (partial PASS post-mortem).")
            return 2
        print("[WARN] --allow-partial set; writing output despite PASS failure")

    parquet_sha = write_parquet(records, out_parquet)
    print(f"[parquet] {out_parquet} sha256 {parquet_sha}")

    directory_sha = file_sha256(directory_path)
    labels_sha = file_sha256(labels_path)
    write_manifest(
        out_path=out_manifest,
        parquet_path=out_parquet,
        parquet_sha=parquet_sha,
        n_records=stats["n_records"],
        stats=stats,
        label_stats=label_idx["stats"],
        directory_sha=directory_sha,
        labels_sha=labels_sha,
    )
    print(f"[manifest] {out_manifest}")
    print(f"[total] {time.time()-t0:.2f}s")
    return 0 if (rec_pass and mj_pass) else 2


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--directory", default="data/vasp_directory_v2.json",
                        help="Path to vasp_directory_v2.json")
    common.add_argument("--labels", required=True,
                        help="Path to a unified label store JSON")

    sp_profile = sub.add_parser("profile", parents=[common],
                                 help="Coverage profile only (no output written)")
    sp_profile.set_defaults(func=cmd_profile)

    sp_build = sub.add_parser("build", parents=[common],
                               help="Full build → parquet + manifest")
    sp_build.add_argument("--output", default="data/vasp_to_address_v1.parquet",
                          help="Output parquet path")
    sp_build.add_argument("--allow-partial", action="store_true",
                          help="Write output even if PASS criteria fail (post-mortem path)")
    sp_build.set_defaults(func=cmd_build)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
