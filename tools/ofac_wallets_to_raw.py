#!/usr/bin/env python3
"""Convert `ofac_wallets.json` (fetch_ofac_primary output) into the raw-record
shape consumed by `openlabels.pipelines.merge_to_unified`.

Bridges the live-OFAC path to the same merge → TagPack chain the determinism
test runs on the fixed subset: one raw record per wallet row, chain inferred
from the OFAC currency ticker + address format (`ofac_attributed._infer_chain`).
Rows whose chain cannot be inferred are counted and skipped, never guessed.

Usage:
    python3 tools/ofac_wallets_to_raw.py --wallets ofac/ofac_wallets.json \
        --source-date 2026-08-25 --out raw/ofac_live.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from openlabels.ofac_attributed import _infer_chain


def convert(rows: list[dict], source_date: str) -> tuple[list[dict], dict[str, int]]:
    records: list[dict] = []
    skipped: dict[str, int] = {}
    for r in rows:
        chain = _infer_chain(r["currency"], r["address"])
        if not chain or chain == "unknown":
            skipped[r["currency"]] = skipped.get(r["currency"], 0) + 1
            continue
        name = r.get("entity_name") or f"OFAC SDN {r['entity_id']}"
        records.append(
            {
                "address": r["address"],
                "chain": chain,
                "labels": [
                    {
                        "name": name,
                        "type": "sanctioned",
                        "source": "ofac_sdn",
                        "chain": chain,
                    }
                ],
                "is_illicit": True,
                "is_exchange": False,
                "is_ai_agent": False,
                "entity_name": name,
                "category": "sanctioned",
                "sanctioned": True,
                "sanctions_reference": f"OFAC SDN-{r['entity_id']}",
                "source_date": source_date,
            }
        )
    return records, skipped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--wallets", required=True, type=Path)
    ap.add_argument("--source-date", required=True,
                    help="publication date carried into every record (YYYY-MM-DD)")
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args()

    rows = json.loads(a.wallets.read_text())
    records, skipped = convert(rows, a.source_date)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(records, ensure_ascii=False))
    print(f"records: {len(records)}  skipped_by_currency: {json.dumps(skipped, sort_keys=True)}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
