#!/usr/bin/env python3
"""US FinCEN MSB Registrant scraper.

Source: msb.fincen.gov/retrieve.msb.list.php — public MSB Registrant
Search portal exposed by FinCEN as a POST endpoint that returns a TSV
(tab-separated) bulk dump filtered by activity / geography. Discovery
2026-05-15: form fields enumerated from msb.fincen.gov/;
SrchMSBState=ALL + SrchSrvOffered=409
returns all national Money Transmitters in one POST (~31K rows).

Note on CVC tagging: the public TSV does NOT include an explicit
"Convertible Virtual Currency" activity flag (FinCEN's internal CVC
designation is filed but not exposed by the bulk export). Practical
filter combines two layers:

  (a) MSB activity = 409 (Money Transmitter) — required, since CVC
      activity is filed under MT category.
  (b) Name-keyword match on crypto/Web3 terms OR explicit allowlist
      of well-known crypto MSBs (Coinbase, Kraken, Gemini, Circle,
      BitGo, Anchorage, Paxos, Ripple, Robinhood Crypto, Zero Hash,
      Galaxy, Wintermute, Stripe Crypto, Bakkt, etc.).

Result: a high-precision crypto-MSB subset citable to FinCEN MSB
Registrant Search per row.

Output: data/labels_raw/fincen_msb_vasps_<date>.json with one
UnifiedLabelRecord per entity.
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date
from pathlib import Path

FINCEN_POST = "https://msb.fincen.gov/retrieve.msb.list.php"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Crypto-name keywords (case-insensitive substring match on legal_name + dba_name).
# Tuned to balance recall (catch Web3 / DeFi naming) vs precision (avoid false
# positives like "Coinstar Inc." which is a coin-counting kiosk).
CRYPTO_KEYWORDS = [
    "crypto", "bitcoin", " btc ", "btc.",
    "ethereum", "eth ", "eth.",
    "blockchain", "web3", "defi", "dao",
    "digital asset", "digital-asset", "digitalasset",
    "virtual currency", "virtual-currency",
    "stablecoin", "stable coin",
    "wallet",
    "mining pool",
    "tokenized", "tokenisation",
    "nft", "metaverse",
    "ledger", "decentralized",
    " dex ", "dex.", "swap.",
]

# Explicit allowlist of known crypto MSBs that may not match keywords
# (e.g. branded names like "Kraken" that don't carry "crypto" in legal name).
# Substring match on legal_name OR dba_name (case-insensitive).
KNOWN_CRYPTO_MSBS = [
    "coinbase", "kraken", "payward",
    "gemini", "circle internet", "paxos",
    "bitgo", "anchorage", "ripple", "robinhood crypto",
    "zero hash", "galaxy digital", "wintermute",
    "stripe", "bakkt", "moonpay",
    "block.one", "blockfi", "binance",
    "okx", "bybit", "bitstamp", "kucoin",
    "okcoin", "bittrex", "poloniex",
    "celsius", "voyager", "nexo",
    "huobi", "ftx", "crypto.com", "foris dax",
    "uphold", "abra", "river financial", "cash app",
    "swan bitcoin", "strike", "fold app",
    "ondo", "anchor labs", "fireblocks",
    "chainalysis", "consensys", "metamask",
    "lightning labs", "lightspark",
    "tether", "usdc", "usdt",
    "consensys", "polygon labs", "matter labs",
    "alchemy", "infura",
    "trm labs", "elliptic",
    "talos", "fpg", "falconx", "genesis", "amber",
    "republic", "edx", "lmax digital",
    "cumberland", "drw", "jane street crypto",
    "anchor digital", "komainu", "bnymellon digital",
    "fidelity digital", "nydig",
    "zero exchange", "uniswap", "aave", "compound",
    "maker dao",
    "solana", "ripple", "stellar",
    "bittensor",
    "river", "swan", "unchained capital",
]


@dataclass(frozen=True)
class FincenMsb:
    legal_name: str
    dba_name: str
    address: str
    city: str
    state: str
    zip_code: str
    activities: str  # space-separated codes e.g. "401 402 409"
    states_offered: str  # space-separated state codes
    foreign_flag: str
    foreign_location: str
    branches: int
    auth_date: str  # MM/DD/YYYY
    received_date: str  # MM/DD/YYYY


def fetch_msb_tsv(service_code: str, timeout: int = 120) -> str:
    """POST to FinCEN MSB Registrant Search; returns TSV body as text."""
    payload = urllib.parse.urlencode({
        "site": "AA",
        "SrchBSAID": "",
        "SrchBusinessName": "",
        "SrchAlias": "",
        "SrchMSBAddress": "",
        "SrchMSBCity": "",
        "SrchMSBState": "ALL",
        "SrchMSBZipCode": "",
        "SrchSrvOffered": service_code,
        "SrchSrvState": "",
        "SrchForeignCode": "",
        "submit": "Search",
    }).encode("ascii")
    req = urllib.request.Request(
        FINCEN_POST,
        data=payload,
        method="POST",
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_tsv(body: str) -> list[FincenMsb]:
    lines = body.split("\n")
    if not lines:
        return []
    header = lines[0].split("\t")
    if "LEGAL NAME" not in header[0].upper():
        raise RuntimeError(f"Unexpected header: {header[:3]!r}")
    rows: list[FincenMsb] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) < 13:
            continue
        try:
            branches = int(cols[10].strip() or "0")
        except ValueError:
            branches = 0
        rows.append(FincenMsb(
            legal_name=cols[0].strip(),
            dba_name=cols[1].strip(),
            address=cols[2].strip(),
            city=cols[3].strip(),
            state=cols[4].strip(),
            zip_code=cols[5].strip(),
            activities=cols[6].strip(),
            states_offered=cols[7].strip(),
            foreign_flag=cols[8].strip(),
            foreign_location=cols[9].strip(),
            branches=branches,
            auth_date=cols[11].strip(),
            received_date=cols[12].strip(),
        ))
    return rows


def is_crypto_msb(row: FincenMsb) -> bool:
    blob = f" {row.legal_name.lower()} | {row.dba_name.lower()} "
    if any(kw in blob for kw in CRYPTO_KEYWORDS):
        return True
    if any(name in blob for name in KNOWN_CRYPTO_MSBS):
        return True
    return False


def normalize_iso_date(mmddyyyy: str) -> str | None:
    m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})$", mmddyyyy.strip())
    if not m:
        return None
    mm, dd, yyyy = m.groups()
    return f"{yyyy}-{int(mm):02d}-{int(dd):02d}"


def to_unified_record(row: FincenMsb, today: date) -> dict:
    name_for_addr = (row.legal_name or row.dba_name).lower().replace(" ", "_")[:60]
    issued = normalize_iso_date(row.auth_date)
    return {
        "address": f"fincen::{name_for_addr}",
        "chain": "multi",
        "labels": [
            {
                "name": row.legal_name or row.dba_name,
                "type": "exchange",
                "source": "fincen_msb",
                "chain": "multi",
            }
        ],
        "is_exchange": True,
        "is_illicit": False,
        "is_ai_agent": False,
        "entity_name": row.legal_name or row.dba_name,
        "category": "vasp",
        "jurisdiction": "US",
        "license_id": None,  # FinCEN MSB Registrant Search does not surface a public ID in bulk export
        "regulator": "Financial Crimes Enforcement Network (FinCEN)",
        "license_status": "active",  # FinCEN bulk dump only lists currently-registered MSBs
        "sanctioned": False,
        "source_url": "https://msb.fincen.gov/retrieve.msb.list.php",
        "source_date": today.isoformat(),
        "_fincen_dba_name": row.dba_name or None,
        "_fincen_address": row.address or None,
        "_fincen_state": row.state or None,
        "_fincen_zip": row.zip_code or None,
        "_fincen_activities": row.activities or None,
        "_fincen_states_offered": row.states_offered or None,
        "_fincen_foreign_location": row.foreign_location or None,
        "_fincen_auth_date": issued,
        "_fincen_received_date": normalize_iso_date(row.received_date),
        "_fincen_branches": row.branches,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / "labels_raw" /
        f"fincen_msb_vasps_{date.today().isoformat()}.json",
    )
    parser.add_argument(
        "--service-codes",
        nargs="+",
        default=["409", "499"],  # Money Transmitter + Other (where CVC may be filed)
        help="MSB activity codes to fetch (default: 409 Money Transmitter + 499 Other)",
    )
    args = parser.parse_args()

    today = date.today()

    all_rows: list[FincenMsb] = []
    by_code: dict[str, int] = {}
    for code in args.service_codes:
        print(f"Fetching service code {code} ...", flush=True)
        body = fetch_msb_tsv(code)
        rows = parse_tsv(body)
        by_code[code] = len(rows)
        print(f"  code {code}: {len(rows):,} rows", flush=True)
        all_rows.extend(rows)

    # Dedupe on (legal_name, address, state) — same firm can register under multiple codes
    seen: set[tuple[str, str, str]] = set()
    deduped: list[FincenMsb] = []
    for r in all_rows:
        key = (r.legal_name.lower(), r.address.lower(), r.state.lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
    print(f"After dedupe: {len(deduped):,} unique MSBs across codes {args.service_codes}",
          flush=True)

    crypto_rows = [r for r in deduped if is_crypto_msb(r)]
    print(f"Crypto-filtered: {len(crypto_rows):,} entities matching crypto keywords / "
          f"known-MSB allowlist", flush=True)

    records = [to_unified_record(r, today) for r in crypto_rows]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)

    # Summary
    by_state: dict[str, int] = {}
    domestic_count = 0
    foreign_count = 0
    for r in crypto_rows:
        by_state[r.state] = by_state.get(r.state, 0) + 1
        if r.foreign_location:
            foreign_count += 1
        else:
            domestic_count += 1

    print("\nSummary:")
    print(f"  Total fetched (raw): {sum(by_code.values()):,}")
    for code, n in by_code.items():
        print(f"    code {code}: {n:,}")
    print(f"  Unique post-dedupe: {len(deduped):,}")
    print(f"  Crypto-filtered:    {len(crypto_rows):,}")
    print(f"    domestic: {domestic_count:,} | foreign: {foreign_count:,}")
    print("\nTop 10 states by crypto-MSB count:")
    for st, n in sorted(by_state.items(), key=lambda kv: -kv[1])[:10]:
        print(f"  {st:5s}  {n}")
    print(f"\nOutput: {args.output}")


if __name__ == "__main__":
    main()
