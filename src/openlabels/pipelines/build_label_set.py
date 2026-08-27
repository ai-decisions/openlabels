#!/usr/bin/env python3
"""Append-only label-set builder with an explicit `provenance` column.

Folds an attributed label batch into an existing label set, APPEND-ONLY.
Each batch row is an attribution derived from a first-party anchor (OFAC /
court / licensed-VASP registry / on-chain fact), carrying source_url +
source_date.

Guarantees (asserted at build time — a violation HALTs, nothing is written):
  * append-only: every (chain, address) key in the base survives; row count
    never shrinks.
  * case-intact: a batch address that is case-destroyed (is_case_destroyed)
    or a synthetic '::' key (no on-chain address) is REFUSED, never ingested.
  * provenance: every row carries a `provenance` array; base rows get [];
    each attributed add/merge appends one JSON provenance entry
    {batch_id, anchor_type, method, source_url, source_date, attributed_utc}.

Batch input: JSONL, one object per line:
  {"chain":"eth","address":"0x…","classes":["exchange","vasp:alias::binance"],
   "anchor_type":"ofac|court|registry|onchain","method":"…",
   "source_url":"https://…","source_date":"2026-08-01","note":"…"}

The merge logic (`merge_batch`) is a pure function unit-tested offline; `main`
does the parquet I/O.

Usage:
    python3 -m openlabels.pipelines.build_label_set \
        --base label_set.parquet --batch attribution_batch.jsonl \
        --batch-id batch-01 --out-dir out/ [--execute]
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from openlabels.address_case import canonical_case, is_case_destroyed
from openlabels.tron_address import InvalidTronAddress, base58check_to_hex

CHAIN_NORM = {
    "ethereum": "eth", "eth": "eth",
    "xdai": "gnosis", "gnosis": "gnosis",
    "arbitrum": "arbitrum", "arb": "arbitrum",
    "base": "base", "tron": "tron", "trx": "tron",
    "btc": "btc", "bitcoin": "btc",
}
INCLUDED = {"eth", "tron", "base", "arbitrum", "gnosis"}


def norm_chain(c: str) -> str:
    c = (c or "").strip().lower()
    return CHAIN_NORM.get(c, c)


def make_provenance(rec: dict, batch_id: str, now_iso: str) -> str:
    """One JSON provenance entry for an attributed row."""
    return json.dumps(
        {
            "batch_id": batch_id,
            "anchor_type": rec.get("anchor_type"),
            "method": rec.get("method"),
            "source_url": rec.get("source_url"),
            "source_date": rec.get("source_date"),
            "attributed_utc": now_iso,
            "note": rec.get("note"),
        },
        sort_keys=True,
        ensure_ascii=False,
    )


class BatchRefused(Exception):  # noqa: N818 — refusal signal, not an error condition
    pass


class AppendOnlyViolation(RuntimeError):  # noqa: N818 — invariant name, matches repo precedent
    """Raised (never assert — `python -O` must not disable it) when a merge
    would drop a base key or shrink the set."""


def validate_batch_row(rec: dict) -> tuple[str, str]:
    """Return (chain, canonical_address) or raise BatchRefused with a reason."""
    addr = (rec.get("address") or "").strip()
    if not addr:
        raise BatchRefused("no address")
    if "::" in addr:
        raise BatchRefused("synthetic '::' key (no on-chain address)")
    chain = norm_chain(rec.get("chain"))
    if not chain:
        raise BatchRefused("no chain")
    a = canonical_case(addr)
    # Tron: the product/graph key form is 0x-hex (0x41 prefix stripped). A
    # base58 T-form batch address is normalized to hex here — otherwise it
    # would create a ('tron', 'T…') key unreachable by product lookups (the
    # key-symmetry defect class).
    if chain == "tron" and len(a) == 34 and a[0] == "T":
        try:
            a = base58check_to_hex(a)
        except InvalidTronAddress:
            raise BatchRefused("invalid tron base58check address") from None
    if is_case_destroyed(a, chain):
        raise BatchRefused("case-destroyed address")
    if not rec.get("source_url") or not rec.get("source_date"):
        raise BatchRefused("missing source_url/source_date provenance")
    cls = rec.get("classes") or []
    if not isinstance(cls, list) or not cls:
        raise BatchRefused("no classes")
    return chain, a


def merge_batch(
    base: dict[tuple[str, str], dict],
    batch: list[dict],
    batch_id: str,
    now_iso: str,
) -> tuple[dict[tuple[str, str], dict], dict]:
    """Pure append-only merge of an attributed *batch* onto *base* rows.

    *base* maps (chain, address) -> row dict with at least keys
    classes/sources/origins/graph_key/provenance (provenance defaulted to []).
    Returns (rows, stats). Never removes a base key. Refused rows are counted,
    not merged.
    """
    rows = {k: dict(v) for k, v in base.items()}
    for r in rows.values():
        r.setdefault("provenance", [])
        r["classes"] = set(r.get("classes") or [])
        r["sources"] = set(r.get("sources") or [])
        r["origins"] = set(r.get("origins") or [])

    base_keys = set(rows)
    st = collections.Counter()
    refused: list[dict] = []
    origin = f"attribution_batch:{batch_id}"

    for rec in batch:
        try:
            chain, a = validate_batch_row(rec)
        except BatchRefused as e:
            st[f"refused:{e}"] += 1
            refused.append({"row": rec, "reason": str(e)})
            continue
        key = (chain, a)
        prov = make_provenance(rec, batch_id, now_iso)
        classes = set(rec.get("classes") or [])
        if key in rows:
            row = rows[key]
            row["classes"] |= classes
            row["sources"].add(origin)
            row["origins"].add(origin)
            row["provenance"] = list(row.get("provenance") or []) + [prov]
            st["merged_into_existing"] += 1
        else:
            rows[key] = {
                "chain": chain,
                "address": a,
                "classes": classes,
                "sources": {origin},
                "origins": {origin},
                "graph_key": f"{chain}:{a}" if chain in INCLUDED else None,
                "case_broken": False,
                "case_provenance": f"attributed:{batch_id}",
                "label_addr_original": None,
                "provenance": [prov],
            }
            st["added_new"] += 1

    # append-only invariant — explicit exception, not assert (-O safe)
    if not base_keys <= set(rows):
        raise AppendOnlyViolation("base key dropped")
    if len(rows) < len(base):
        raise AppendOnlyViolation("row count shrank")

    stats = {
        "batch_rows": len(batch),
        "added_new": st["added_new"],
        "merged_into_existing": st["merged_into_existing"],
        "refused_total": len(refused),
        "refused_breakdown": {k: v for k, v in st.items() if k.startswith("refused:")},
        "refused_rows": refused,
    }
    return rows, stats


def rows_to_table(recs: list[dict]):
    """Materialize merged rows as an arrow table. Schema = the base schema
    (incl. `in_included_5`, which downstream gates read)
    + the `provenance` column."""
    import pyarrow as pa

    return pa.table({
        "chain": [r["chain"] for r in recs],
        "address": [r["address"] for r in recs],
        "classes": [sorted(r["classes"]) for r in recs],
        "sources": [sorted(r["sources"]) for r in recs],
        "origins": [sorted(r["origins"]) for r in recs],
        "graph_key": [r["graph_key"] for r in recs],
        "case_broken": [r["case_broken"] for r in recs],
        "case_provenance": [r["case_provenance"] for r in recs],
        "label_addr_original": [r["label_addr_original"] for r in recs],
        "in_included_5": [r["chain"] in INCLUDED for r in recs],
        "provenance": [list(r.get("provenance") or []) for r in recs],
    })


# --------------------------------------------------------------------------- #
# Local parquet build                                                          #
# --------------------------------------------------------------------------- #
def load_base_parquet(
    path: Path | None, manifest_path: Path | None = None
) -> dict[tuple[str, str], dict]:
    """Load the base label set from a local parquet (or start empty).

    When a manifest is given, the parquet is verified against its recorded
    sha256 and row count before anything is merged — fail-closed: a manifest
    without those keys HALTs rather than silently skipping the check.
    """
    if path is None:
        return {}
    import pyarrow.parquet as pq

    raw = path.read_bytes()
    man = None
    if manifest_path is not None:
        man = json.loads(manifest_path.read_text())
        if not man.get("parquet_sha256"):
            sys.exit("HALT: base manifest carries no parquet_sha256 — cannot verify base")
        got = hashlib.sha256(raw).hexdigest()
        if got != man["parquet_sha256"]:
            sys.exit(f"HALT: base parquet sha mismatch {got[:20]} != manifest")
    import io as _io

    t = pq.read_table(_io.BytesIO(raw))
    base: dict[tuple[str, str], dict] = {}
    cols = {c: t.column(c).to_pylist() for c in t.column_names}
    for i in range(t.num_rows):
        ch, ad = cols["chain"][i], cols["address"][i]
        base[(ch, ad)] = {
            "chain": ch, "address": ad,
            "classes": cols["classes"][i] or [],
            "sources": cols["sources"][i] or [],
            "origins": cols["origins"][i] or [],
            "graph_key": cols["graph_key"][i],
            "case_broken": cols["case_broken"][i],
            "case_provenance": cols["case_provenance"][i],
            "label_addr_original": cols["label_addr_original"][i],
            "provenance": [],
        }
    if len(base) != t.num_rows:
        sys.exit(f"HALT: loaded {len(base)} rows != {t.num_rows} (duplicate keys?)")
    if man is not None and man.get("rows_total") is not None and man["rows_total"] != t.num_rows:
        sys.exit(f"HALT: base rows {t.num_rows} != manifest rows_total {man['rows_total']}")
    return base


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", type=Path, default=None,
                    help="base label-set parquet (omit to start empty)")
    ap.add_argument("--base-manifest", type=Path, default=None,
                    help="manifest.json of the base parquet (sha verified when given)")
    ap.add_argument("--batch", required=True, help="attribution batch JSONL")
    ap.add_argument("--batch-id", required=True)
    ap.add_argument("--out-dir", type=Path, default=Path("out"),
                    help="output directory for parquet + manifest")
    ap.add_argument("--attributed-utc", default=None,
                    help="override the attributed_utc timestamp (ISO8601) for "
                         "reproducible builds; default: now")
    ap.add_argument("--execute", action="store_true", help="write output; default dry-run")
    args = ap.parse_args()

    import pyarrow.parquet as pq

    now_iso = args.attributed_utc or datetime.now(UTC).isoformat()

    base = load_base_parquet(args.base, args.base_manifest)
    batch = [json.loads(line)
             for line in Path(args.batch).read_text().splitlines() if line.strip()]

    rows, stats = merge_batch(base, batch, args.batch_id, now_iso)

    recs = sorted(rows.values(), key=lambda r: (r["chain"], r["address"]))
    table = rows_to_table(recs)

    per_chain = collections.Counter(r["chain"] for r in recs)
    per_chain_base = collections.Counter(k[0] for k in base)
    rows_with_prov = sum(1 for r in recs if r.get("provenance"))

    manifest = {
        "name": "label_set",
        "definition": ("base label set + append-only attributed batch "
                       "with provenance column"),
        "built_utc": now_iso,
        "base": {"file": str(args.base) if args.base else None, "rows": len(base)},
        "batch_id": args.batch_id,
        "batch": {k: v for k, v in stats.items() if k != "refused_rows"},
        "rows_total": len(recs),
        "rows_added_vs_base": len(recs) - len(base),
        "rows_with_provenance": rows_with_prov,
        "per_chain": dict(sorted(per_chain.items())),
        "diff_vs_base": {
            "rows_total": {"base": len(base), "new": len(recs), "delta": len(recs) - len(base)},
            "per_chain_delta": {ch: per_chain.get(ch, 0) - per_chain_base.get(ch, 0)
                                for ch in sorted(set(per_chain) | set(per_chain_base))
                                if per_chain.get(ch, 0) != per_chain_base.get(ch, 0)},
        },
        "append_only_verified": True,
        "notes": [
            "APPEND-ONLY: every base (chain,address) key retained; row count never shrinks (asserted).",
            "case-intact: case-destroyed / synthetic '::' batch rows refused, not ingested.",
            "provenance[] holds JSON entries; base rows carry [] (added only on attribution).",
        ],
    }

    print(json.dumps({k: manifest[k] for k in
                      ("rows_total", "rows_added_vs_base", "rows_with_provenance",
                       "batch", "diff_vs_base")}, indent=2, ensure_ascii=False))
    if stats["refused_rows"]:
        print(f"-- {len(stats['refused_rows'])} refused (first 5): "
              f"{json.dumps(stats['refused_rows'][:5], ensure_ascii=False)}", file=sys.stderr)

    if not args.execute:
        print("-- DRY RUN. Nothing written. Pass --execute to write.", file=sys.stderr)
        return 0

    import io as _io

    buf = _io.BytesIO()
    pq.write_table(table, buf, compression="snappy")
    data = buf.getvalue()
    manifest["parquet_sha256"] = hashlib.sha256(data).hexdigest()
    manifest["parquet_bytes"] = len(data)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_parquet = args.out_dir / "label_set.parquet"
    out_parquet.write_bytes(data)
    (args.out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False)
    )
    print(f"WROTE {out_parquet} "
          f"({len(data)} B, sha {manifest['parquet_sha256'][:16]}…) + manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
