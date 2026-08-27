#!/usr/bin/env python3
"""Fetch Tronscan public VASP-tagged addresses.

Pagination strategy: Tronscan `/api/account/list?order=totalBalance`
tops out at 10,000 accounts. A naive sweep returns ~3-5% tagged
accounts (hot/cold wallet labels like "Binance-Hot 1", "HTX-Cold 4").
With an API key, `/api/accountv2?address=<addr>` also yields per-address
tags, which lets us follow seed addresses into deposit clusters in a
future iteration. This first pass does the top-10k sweep only.

Tronscan public tags are citable (logo URL included) — suitable for
DD audit trails.

Usage:
    TRONSCAN_API_KEY=<key> python3 -m openlabels.pipelines.scrape_tronscan_vasps
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import date
from pathlib import Path

from openlabels.tron_address import InvalidTronAddress, base58check_to_hex

API_BASE = "https://apilist.tronscanapi.com"
SOURCE_URL_TEMPLATE = "https://tronscan.org/#/address/{address}"


VASP_CATEGORIES: dict[str, tuple[str, str]] = {
    # First token of publicTag → (canonical_entity_name, jurisdiction_iso)
    "Binance": ("Binance", "KY"),
    "HTX": ("HTX", "SC"),
    "Huobi": ("HTX", "SC"),
    "OKX": ("OKX", "KY"),
    "Bybit": ("Bybit", "AE"),
    "KuCoin": ("KuCoin", "SC"),
    "Kucoin": ("KuCoin", "SC"),
    "Kraken": ("Kraken", "US"),
    "Gate": ("Gate.io", "KY"),
    "MXC": ("MEXC", "SC"),
    "MEXC": ("MEXC", "SC"),
    "Bitfinex": ("Bitfinex", "VG"),
    "Bithumb": ("Bithumb", "KR"),
    "Upbit": ("Upbit", "KR"),
    "Poloniex": ("Poloniex", "US"),
    "BigONE": ("BigONE", "HK"),
    "BitPanda": ("Bitpanda", "AT"),
    "Bitpanda": ("Bitpanda", "AT"),
    "FixedFloat": ("FixedFloat", "unknown"),
    "CoinSpot": ("CoinSpot", "AU"),
    "Vaneck": ("VanEck", "US"),
    "Heleket": ("Heleket", "unknown"),
    "TronLucky": ("TronLucky", "unknown"),
    "Upbit:": ("Upbit", "KR"),
    "Kraken:": ("Kraken", "US"),
    "WestWallet": ("WestWallet", "unknown"),
    "SR": ("Super Representative", "unknown"),  # Tron validator, not VASP
}

# Known non-VASP categories (skip: these are not exchanges)
NON_VASP_PREFIXES = {"SR", "JustLend", "SunSwap", "Stake"}


def request_page(
    start: int, limit: int, api_key: str | None, retries: int = 3
) -> list[dict]:
    url = f"{API_BASE}/api/account/list?order=totalBalance&limit={limit}&start={start}"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["TRON-PRO-API-KEY"] = api_key

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.load(resp)
            return payload.get("data", [])
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt == retries - 1:
                print(f"  [start={start}] giving up after {retries} attempts: {exc}")
                return []
            wait = 2 ** attempt
            print(f"  [start={start}] retry {attempt+1}/{retries} after {wait}s ({exc})")
            time.sleep(wait)
    return []


def classify(public_tag: str) -> tuple[str, str, str] | None:
    """Return (entity_name, category, jurisdiction) or None if not VASP."""
    first = public_tag.split("-")[0].split()[0].rstrip(":")
    if first in NON_VASP_PREFIXES:
        return None
    mapping = VASP_CATEGORIES.get(first)
    if not mapping:
        # Unknown but has a tag — emit as exchange_depositor with raw name.
        return (first, "exchange_depositor", "unknown")
    entity_name, jurisdiction = mapping
    category = "vasp" if first not in {"Vaneck", "SR"} else "exchange_depositor"
    return (entity_name, category, jurisdiction)


def build_record(
    tronscan_account: dict, source_date: date
) -> dict | None:
    """One Tronscan account row → UnifiedLabelRecord v2.1 dict (or None)."""
    t_addr = tronscan_account["address"]
    tag = tronscan_account.get("addressTag", "")
    if not tag:
        return None
    triple = classify(tag)
    if triple is None:
        return None
    entity_name, category, jurisdiction = triple

    # Convert T-base58 → 0x-hex
    try:
        hex_addr = base58check_to_hex(t_addr)
    except InvalidTronAddress:
        return None

    is_exchange = category in {"vasp", "exchange_depositor"}

    rec = {
        "address": hex_addr,
        "chain": "tron",
        "labels": [
            {
                "name": tag,
                "type": "exchange" if is_exchange else "unknown",
                "source": "tronscan_public",
                "chain": "tron",
            }
        ],
        "is_exchange": is_exchange,
        "is_illicit": False,
        "is_ai_agent": False,
        "entity_name": entity_name,
        "category": category,
        "jurisdiction": jurisdiction if jurisdiction != "unknown" else None,
        "sanctioned": False,
        "source_url": SOURCE_URL_TEMPLATE.format(address=t_addr),
        "source_date": source_date.isoformat(),
        "_tronscan_raw_tag": tag,
        "_tronscan_raw_address": t_addr,
    }
    return rec


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / "labels_raw" /
        f"tronscan_vasps_{date.today().isoformat()}.json",
    )
    parser.add_argument("--max-accounts", type=int, default=10000)
    parser.add_argument("--page-size", type=int, default=50)
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.2,
        help="Seconds between page requests (politeness even with API key)",
    )
    args = parser.parse_args()

    api_key = os.environ.get("TRONSCAN_API_KEY")
    if not api_key:
        print("WARNING: TRONSCAN_API_KEY not set. Request rate will be "
              "heavily limited and may fail early.", file=sys.stderr)

    today = date.today()
    records: list[dict] = []
    total_seen = 0
    tag_hits = 0

    for start in range(0, args.max_accounts, args.page_size):
        page = request_page(start, args.page_size, api_key)
        if not page:
            print(f"[start={start}] empty / failed page — stopping")
            break
        total_seen += len(page)
        for acc in page:
            if acc.get("addressTag"):
                tag_hits += 1
                rec = build_record(acc, today)
                if rec:
                    records.append(rec)
        time.sleep(args.sleep)

    # Dedupe by hex address (multiple tag variants possible for same wallet)
    by_addr: dict[str, dict] = {}
    for rec in records:
        key = rec["address"]
        if key not in by_addr:
            by_addr[key] = rec
        else:
            by_addr[key]["labels"].append(rec["labels"][0])
    out_records = list(by_addr.values())

    entities = Counter(r["entity_name"] for r in out_records)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(out_records, fh, indent=2, ensure_ascii=False)

    print(f"\nScanned:     {total_seen} accounts (top {args.max_accounts})")
    print(f"Tagged:      {tag_hits}")
    print(f"After filter + dedupe: {len(out_records)} records / "
          f"{len(entities)} distinct entities")
    print("\nTop VASPs:")
    for e, n in entities.most_common(15):
        print(f"  {n:3d}  {e}")
    print(f"\nOutput: {args.output}")


if __name__ == "__main__":
    main()
