"""Merge Dune Spellbook addresses into an extended unified label store.

Extends a unified label store with Spellbook-harvested institutional +
CEX addresses (BitGo, Anchorage, Wintermute, MoonPay, etc.). Each
address keeps existing labels and gets a new label entry tagged
`source = "dune_spellbook"` so downstream code can audit provenance.

LICENCE WARNING: Dune Spellbook is BSL 1.1 (see harvest_spellbook.py) —
the merged OUTPUT contains Spellbook-derived rows and must not be
committed to this repository or redistributed.

Chain:
    1. python3 -m openlabels.pipelines.harvest_spellbook
       → data/labels_raw/dune_spellbook_addresses.json
    2. python3 -m openlabels.pipelines.merge_spellbook_into_unified
       → data/unified_labels_extended.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--base", default="data/unified_labels_current.json",
                   help="Path to unified_labels_current.json (baseline)")
    p.add_argument("--spellbook", default="data/labels_raw/dune_spellbook_addresses.json",
                   help="Path to dune_spellbook_addresses.json from harvest_spellbook.py")
    p.add_argument("--output", default="data/unified_labels_extended.json",
                   help="Output extended unified_labels JSON path")
    args = p.parse_args()

    base_path = Path(args.base)
    spellbook_path = Path(args.spellbook)
    out_path = Path(args.output)

    existing = json.loads(base_path.read_text())
    print(f"baseline addresses: {len(existing):,}")

    spellbook = json.loads(spellbook_path.read_text())
    print(f"spellbook records: {len(spellbook):,}")

    by_addr: dict[str, list[dict]] = defaultdict(list)
    for r in spellbook:
        by_addr[r["address"]].append(r)
    print(f"distinct spellbook addresses: {len(by_addr):,}")

    augmented = 0
    added = 0
    for addr, recs in by_addr.items():
        first = recs[0]
        chain = first["chain"]

        if addr in existing:
            ex = existing[addr]
            for r in recs:
                ex.setdefault("labels", []).append({
                    "name": r["entity_name"] + (
                        f" {r['distinct_name']}"
                        if r.get("distinct_name") and r["distinct_name"] != r["entity_name"]
                        else ""
                    ),
                    "type": "exchange",
                    "subtype": r["entity_name"].lower().replace(" ", "_"),
                    "source": "dune_spellbook",
                    "chain": chain,
                })
            ex["is_exchange"] = True
            augmented += 1
        else:
            existing[addr] = {
                "address": addr,
                "chain": chain,
                "is_exchange": True,
                "is_ai_agent": False,
                "is_illicit": False,
                "labels": [
                    {
                        "name": r["entity_name"],
                        "type": "exchange",
                        "subtype": r["entity_name"].lower().replace(" ", "_"),
                        "source": "dune_spellbook",
                        "chain": chain,
                    }
                    for r in recs
                ],
            }
            added += 1

    print(f"augmented {augmented:,} existing addresses, added {added:,} novel")
    print(f"total addresses now: {len(existing):,}")

    out_path.write_text(json.dumps(existing, ensure_ascii=False))
    print(f"wrote {out_path} ({out_path.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
