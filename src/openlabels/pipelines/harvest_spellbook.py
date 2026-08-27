"""Harvest Dune Spellbook CEX + institutional address labels.

Pulls SQL files from https://github.com/duneanalytics/spellbook (raw GitHub),
parses VALUES tuples for address+entity_name+chain, and emits a flat JSON of
records suitable for merging into unified_labels.

LICENCE WARNING: Dune Spellbook is licensed BSL 1.1 (verified 2026-08-23;
it was MIT until 2023 — do not rely on stale "Apache-2.0" notes). The BSL
Additional Use Grant excludes use for a "Data or Analytics Platform".
The OUTPUT of this harvester is a derivative of the Spellbook: do not
commit it to this repository, do not redistribute it, and assess your own
use against the BSL grant before running this in production.

Usage:
    python3 -m openlabels.pipelines.harvest_spellbook \
        --output data/labels_raw/dune_spellbook_addresses.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

TREE_URL = "https://api.github.com/repos/duneanalytics/spellbook/git/trees/main?recursive=1"
RAW_BASE = "https://raw.githubusercontent.com/duneanalytics/spellbook/main/"

INCLUDE_KEYWORDS = [
    "cex_",
    "cex/",
    "labels_funds",
    "staking_ethereum_entities_depositor",
    "institution",
    "/cex_evms_",
    "institution/identifier",
]
EXCLUDE_KEYWORDS = ["/test_", "README", ".md", ".yml"]

UA = "aidecisions-labels/1.0"

# 5-tuple CEX pattern: (0xADDR, 'cex_name', 'distinct', 'added_by', date 'YYYY-MM-DD')
CEX_PAT = re.compile(
    r"\((0x[0-9a-fA-F]{40}),\s*'([^']+)',\s*'([^']*)',\s*'([^']*)',\s*date\s+'([^']+)'\)"
)
# 10-tuple labels pattern: ('chain', 0xADDR, 'name', 'category', ...)
LBL_PAT = re.compile(
    r"\(\s*'(ethereum|bnb|polygon|arbitrum|optimism|base|avalanche_c|fantom|gnosis|celo|linea|scroll|zksync)',\s*"
    r"(0x[0-9a-fA-F]{40}),\s*'([^']+)',\s*'([^']*)'"
)


def fetch(url: str, retries: int = 3) -> str | None:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception as e:
            if attempt == retries - 1:
                print(f"  FAIL {url}: {e}", file=sys.stderr)
                return None
            time.sleep(2 * (attempt + 1))
    return None


def list_candidate_files() -> list[str]:
    raw = fetch(TREE_URL)
    if not raw:
        raise SystemExit("could not fetch spellbook tree")
    tree = json.loads(raw).get("tree", [])
    out: list[str] = []
    for t in tree:
        p = t.get("path", "")
        pl = p.lower()
        if not pl.endswith(".sql"):
            continue
        if not any(k in pl for k in INCLUDE_KEYWORDS):
            continue
        if any(k in p for k in EXCLUDE_KEYWORDS):
            continue
        out.append(p)
    return out


def parse_file(path: str, body: str) -> list[dict]:
    out: list[dict] = []
    for addr, name, dist, _by, _dt in CEX_PAT.findall(body):
        out.append({
            "address": addr.lower(),
            "chain": "ethereum",
            "entity_name": name,
            "distinct_name": dist or None,
            "category": "exchange",
            "source_file": path,
        })
    for chain, addr, name, category in LBL_PAT.findall(body):
        out.append({
            "address": addr.lower(),
            "chain": chain,
            "entity_name": name,
            "distinct_name": None,
            "category": category,
            "source_file": path,
        })
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument(
        "--output",
        default="data/labels_raw/dune_spellbook_addresses.json",
        help="Output JSON path",
    )
    args = p.parse_args()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print("Fetching candidate file list from Spellbook tree...")
    candidates = list_candidate_files()
    print(f"  {len(candidates)} candidate SQL files")

    records: list[dict] = []
    file_stats: list[tuple[str, int]] = []
    for i, path in enumerate(candidates):
        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{len(candidates)}] {path}")
        body = fetch(RAW_BASE + path)
        if not body:
            continue
        recs = parse_file(path, body)
        if recs:
            file_stats.append((path, len(recs)))
        records.extend(recs)

    print(f"\n=== file stats ({len(file_stats)} files with records) ===")
    for fp, cnt in file_stats:
        print(f"  {cnt:>5}  {fp}")

    print(f"\n=== total records: {len(records)} ===")
    ent_ctr = Counter(r["entity_name"] for r in records)
    print(f"distinct entities: {len(ent_ctr)}")
    print("\ntop 30 by address count:")
    for n, c in ent_ctr.most_common(30):
        print(f"  {c:>5}  {n}")

    out_path.write_text(json.dumps(records, indent=2, ensure_ascii=False))
    print(f"\nwrote {out_path} ({out_path.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
