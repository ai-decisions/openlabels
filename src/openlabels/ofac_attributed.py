"""OFAC SDN parser producing attributed entity records.

Returns structured records: (sdn_id, entity_name, programs, address,
chain) — suitable for promoting each sanctioned address into a
`UnifiedLabelRecord` with entity_name + sanctions_reference filled in.

CSV format (from sanctionslistservice.ofac.treas.gov):
    SDN_ID,"ENTITY_NAME",type,programs,title,call_sign,vessel_type,
    tonnage,GRT,vessel_flag,vessel_owner,"REMARKS"

Addresses appear only in REMARKS, after one of these literal prefixes:
    "Digital Currency Address - XBT"   (Bitcoin)
    "Digital Currency Address - ETH"   (Ethereum)
    "Digital Currency Address - USDT"  (Tether, chain ambiguous by prefix)
    "Digital Currency Address - TRX"   (Tron native)
    "Digital Currency Address - XMR"   (Monero)
    "Digital Currency Address - BCH"   (Bitcoin Cash)
    ... and similar

Chain inference rule for USDT (which runs on ETH, Tron, and others):
    - If address matches ^0x[0-9a-fA-F]{40}$           → ethereum
    - If address matches ^T[1-9A-HJ-NP-Za-km-z]{33}$   → tron
    - Otherwise                                        → unknown
"""

from __future__ import annotations

import csv
import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


# Match "Digital Currency Address - <TICKER> <address>" inside remarks.
# Greedy on ticker is fine since tickers are uppercase alnum; address stops
# at the next separator (; or , or whitespace-then-keyword).
_DCA_RE = re.compile(
    r"Digital Currency Address\s*-\s*(?P<ticker>[A-Z]{2,8})\s+" r"(?P<address>[A-Za-z0-9]{20,90})"
)

_EVM_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_TRON_ADDR_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")


@dataclass(frozen=True)
class OfacAttributedAddress:
    """One (address, chain, entity) tuple extracted from SDN CSV."""

    sdn_id: str  # e.g. "45213" (SDN list ID, citable)
    entity_name: str  # e.g. "GAMBASHIDZE, Ilya Andreevich"
    entity_type: str  # "individual" | "entity" | "vessel" | "aircraft" | ""
    programs: str  # sanctions program codes (e.g. "RUSSIA-EO14024")
    ticker: str  # as published: "XBT", "ETH", "USDT", "TRX", ...
    address: str  # original case preserved (EVM lowercased below)
    chain: str  # inferred: "ethereum" | "tron" | "bitcoin" | ...


_TICKER_TO_CHAIN: dict[str, str] = {
    "XBT": "bitcoin",
    "BTC": "bitcoin",
    "BCH": "bitcoin_cash",
    "ETH": "ethereum",
    "TRX": "tron",
    "XMR": "monero",
    "LTC": "litecoin",
    "XRP": "ripple",
    "ZEC": "zcash",
    "DASH": "dash",
    "ARB": "arbitrum",
    "BASE": "base",
}


def _infer_chain(ticker: str, address: str) -> str:
    """Map (ticker, address-format) → chain.

    USDT is the only ambiguous case — it ships on ETH and Tron. We
    disambiguate by address shape. Anything not matching a known shape
    falls back to "unknown" so the caller can decide whether to keep it.
    """
    if ticker == "USDT":
        if _EVM_ADDR_RE.match(address):
            return "ethereum"
        if _TRON_ADDR_RE.match(address):
            return "tron"
        return "unknown"
    return _TICKER_TO_CHAIN.get(ticker, "unknown")


def parse_sdn_csv(csv_path: Path) -> list[OfacAttributedAddress]:
    """Parse SDN CSV into attributed address records.

    Uses csv.reader to handle quoted fields (entity names and remarks
    contain commas and embedded quotes). The SDN CSV has no header.
    """
    records: list[OfacAttributedAddress] = []
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh, quotechar='"', skipinitialspace=False)
        for row in reader:
            if len(row) < 12:
                continue
            sdn_id = row[0].strip()
            entity_name = row[1].strip()
            entity_type = row[2].strip().strip('"')
            programs = row[3].strip().strip('"')
            remarks = row[11]

            for match in _DCA_RE.finditer(remarks):
                ticker = match.group("ticker")
                raw_addr = match.group("address")
                chain = _infer_chain(ticker, raw_addr)
                # Normalize EVM to lowercase; preserve base58 case.
                address = (
                    raw_addr.lower()
                    if chain in {"ethereum", "bitcoin_cash", "arbitrum", "base"}
                    and _EVM_ADDR_RE.match(raw_addr)
                    else raw_addr
                )
                records.append(
                    OfacAttributedAddress(
                        sdn_id=sdn_id,
                        entity_name=entity_name,
                        entity_type=entity_type,
                        programs=programs,
                        ticker=ticker,
                        address=address,
                        chain=chain,
                    )
                )

    logger.info(
        "ofac_attributed_parsed total=%d source=%s",
        len(records),
        csv_path,
    )
    return records


def filter_tron(
    records: list[OfacAttributedAddress],
) -> list[OfacAttributedAddress]:
    """Keep only Tron addresses (TRX native + USDT-on-Tron)."""
    return [r for r in records if r.chain == "tron"]
