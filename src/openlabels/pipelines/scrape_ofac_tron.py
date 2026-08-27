#!/usr/bin/env python3
"""Fetch OFAC SDN, extract Tron addresses with entity attribution.

Output is a JSON array of UnifiedLabelRecord-shaped v2.1 dicts written to
`data/labels_raw/ofac_tron_<YYYY-MM-DD>.json`. Tron base58 T-addresses are
converted to 0x-hex via openlabels.tron_address.

Usage:
    python3 -m openlabels.pipelines.scrape_ofac_tron
    python3 -m openlabels.pipelines.scrape_ofac_tron --output out/ofac_tron.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import urllib.request
from datetime import date
from pathlib import Path

from openlabels.ofac_attributed import (
    filter_tron,
    parse_sdn_csv,
)
from openlabels.tron_address import (
    InvalidTronAddress,
    base58check_to_hex,
)

logger = logging.getLogger(__name__)

SOURCE_URL = (
    "https://sanctionslistservice.ofac.treas.gov/"
    "api/PublicationPreview/exports/SDN.CSV"
)

def _default_sdn_cache() -> Path:
    """Per-user cache path.

    A fixed path in a shared, world-writable /tmp lets any local user
    pre-plant a sanctions list that the exists-and-non-empty check below
    would trust verbatim, silently omitting designations.
    """
    base = Path(os.environ.get("XDG_CACHE_HOME") or "")
    if not base.is_absolute():
        base = Path.home() / ".cache"
    return base / "openlabels" / "sdn.csv"


def fetch_sdn_csv(cache_path: Path | None = None, force_refresh: bool = False) -> Path:
    """Download the SDN CSV to a local cache; return the path.

    Raises:
        RuntimeError: if the download returns an empty body.
    """
    path = cache_path or _default_sdn_cache()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > 0 and not force_refresh:
        logger.info("sdn_csv_cache_hit path=%s size=%d", path, path.stat().st_size)
        return path

    logger.info("sdn_csv_downloading url=%s", SOURCE_URL)
    req = urllib.request.Request(
        SOURCE_URL,
        headers={"User-Agent": "openlabels/1.0 (compliance research)"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    if not data:
        raise RuntimeError(f"OFAC SDN download returned empty body from {SOURCE_URL}")
    path.write_bytes(data)
    logger.info("sdn_csv_downloaded path=%s size=%d", path, len(data))
    return path


def build_record(attr, source_date: date) -> dict | None:
    """Convert one OfacAttributedAddress to a UnifiedLabelRecord-shape dict.

    Returns None if the Tron base58 → hex conversion fails (malformed
    address in SDN, extremely rare but possible — OFAC publishes some
    non-standard mainnet forms for testnet / truncated addresses).
    """
    try:
        hex_addr = base58check_to_hex(attr.address)
    except InvalidTronAddress:
        return None

    return {
        "address": hex_addr,
        "chain": "tron",
        "labels": [
            {
                "name": attr.entity_name,
                "type": "sanctioned",
                "source": "ofac_sdn",
                "chain": "tron",
            }
        ],
        "is_illicit": True,
        "is_exchange": False,
        "is_ai_agent": False,
        "entity_name": attr.entity_name,
        "category": "sanctioned",
        "sanctioned": True,
        "sanctions_reference": f"OFAC SDN-{attr.sdn_id}",
        "source_url": SOURCE_URL,
        "source_date": source_date.isoformat(),
        # Preserve raw T-address + OFAC programs/ticker as extra fields
        # (pydantic extra="allow" keeps them for downstream review).
        "_ofac_raw_address": attr.address,
        "_ofac_ticker": attr.ticker,
        "_ofac_programs": attr.programs,
        "_ofac_entity_type": attr.entity_type,
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / "labels_raw" /
        f"ofac_tron_{date.today().isoformat()}.json",
    )
    parser.add_argument(
        "--sdn-cache",
        type=Path,
        default=None,
        help="Optional SDN CSV cache path; default $XDG_CACHE_HOME/openlabels/sdn.csv",
    )
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Force SDN CSV re-download",
    )
    args = parser.parse_args()

    csv_path = fetch_sdn_csv(
        cache_path=args.sdn_cache, force_refresh=args.force_refresh
    )
    attributed = parse_sdn_csv(csv_path)
    tron = filter_tron(attributed)

    today = date.today()
    records = []
    skipped = 0
    for a in tron:
        rec = build_record(a, today)
        if rec is None:
            skipped += 1
            continue
        records.append(rec)

    # De-duplicate on hex address (SDN lists some addresses under
    # multiple linked entities — keep the first occurrence, append
    # alt entity names into labels[]).
    by_addr: dict[str, dict] = {}
    for rec in records:
        key = rec["address"]
        if key not in by_addr:
            by_addr[key] = rec
        else:
            existing = by_addr[key]
            existing["labels"].append(rec["labels"][0])

    out_records = list(by_addr.values())

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(out_records, fh, indent=2, ensure_ascii=False)

    # Distinct entity count for stdout summary.
    entities = {r["entity_name"] for r in out_records}
    print(f"Parsed SDN CSV: {len(attributed)} total DCA matches")
    print(f"Tron addresses: {len(tron)} (before T→hex)")
    print(f"Converted:      {len(records)} ({skipped} skipped)")
    print(f"After dedupe:   {len(out_records)} addresses / {len(entities)} entities")
    print(f"Output:         {args.output}")


if __name__ == "__main__":
    main()
