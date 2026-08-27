#!/usr/bin/env python3
"""Parse data/labels_raw/crypto_rekts/*.json (liqtags/crypto-rekts repo) →
extract addresses + chain attribution + case attribution, emit raw JSON for
merge_to_unified.py.

Each rekt file describes one scam/hack incident. Extract from:
- `token_address` (primary contract) + `token_addresses` (additional)
- `scamNetworks[].networks.name` → chain (Binance / Ethereum / Tron / ...)
- HTML `description` for additional Tron/ETH addresses mentioned inline
- `proof_link` / `webarchive_link` → source_url

Output: data/labels_raw/crypto_rekts_parsed.json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

# Chain name normalisation (crypto-rekts uses varied spellings)
NETWORK_MAP = {
    "Binance": "bsc",
    "BSC": "bsc",
    "BNB": "bsc",
    "BNB Chain": "bsc",
    "Ethereum": "ethereum",
    "Ethereum Classic": "ethereum_classic",
    "ETH": "ethereum",
    "Polygon": "polygon",
    "Polygon (Matic)": "polygon",
    "Matic": "polygon",
    "Avalanche": "avalanche",
    "AVAX": "avalanche",
    "Arbitrum": "arbitrum",
    "Optimism": "optimism",
    "Base": "base",
    "Fantom": "fantom",
    "Cronos": "cronos",
    "Tron": "tron",
    "TRON": "tron",
    "TRX": "tron",
    "Bitcoin": "bitcoin",
    "BTC": "bitcoin",
    "Solana": "solana",
    "SOL": "solana",
    "Near": "near",
    "Cardano": "cardano",
    "Harmony": "harmony",
    "Heco": "heco",
    "OKEx": "okex",
    "OKC": "okex",
    "xDai": "xdai",
    "Gnosis": "gnosis",
    "Celo": "celo",
    "Moonbeam": "moonbeam",
    "Moonriver": "moonriver",
    "Aurora": "aurora",
}

HEX_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
TRON_B58_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
BTC_LEGACY_RE = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")
BTC_BECH32_RE = re.compile(r"\bbc1[02-9ac-hj-np-z]{38,58}\b")


def extract_addresses_from_text(text: str) -> dict[str, set[str]]:
    """Return {chain: {addr, ...}} mined from free text."""
    if not text:
        return {}
    out: dict[str, set[str]] = {}
    for m in HEX_RE.finditer(text):
        out.setdefault("evm_unknown", set()).add(m.group(0).lower())
    for m in TRON_B58_RE.finditer(text):
        out.setdefault("tron", set()).add(m.group(0))
    for m in BTC_LEGACY_RE.finditer(text):
        out.setdefault("bitcoin", set()).add(m.group(0))
    for m in BTC_BECH32_RE.finditer(text):
        out.setdefault("bitcoin", set()).add(m.group(0).lower())
    return out


def parse_one(
    rekt: dict, source_url_base: str = "https://github.com/liqtags/crypto-rekts",
) -> list[dict]:
    """Emit records from a single rekt JSON file."""
    records = []

    # Chain set from scamNetworks
    declared_chains = set()
    for sn in rekt.get("scamNetworks", []) or []:
        net = sn.get("networks") or {}
        name = (net or {}).get("name") or ""
        chain = NETWORK_MAP.get(name)
        if chain:
            declared_chains.add(chain)

    project_name = rekt.get("project_name") or rekt.get("title") or ""
    scam_type = (rekt.get("scam_type") or {}).get("type") or "scam"
    incident_date = rekt.get("date") or ""
    proof = rekt.get("proof_link") or rekt.get("webarchive_link") or ""
    source_url = proof or f"{source_url_base}/blob/main/rekts/{rekt.get('id', '?')}.json"

    # Is it illicit? Rug-pull / honeypot / exit scam / exploit — all illicit
    # (crypto-rekts lists scams/exploits only), so make_record hardcodes True.

    def make_record(addr: str, chain: str) -> dict:
        return {
            "address": addr.lower() if addr.startswith("0x") else addr,
            "chain": chain,
            "labels": [
                {
                    "name": project_name,
                    "type": scam_type.lower() if scam_type else "scam",
                    "source": "crypto_rekts",
                    "chain": chain,
                }
            ],
            "is_illicit": True,
            "is_exchange": False,
            "is_ai_agent": False,
            "entity_name": project_name,
            "category": "scam",
            "sanctioned": False,
            "sanctions_reference": None,
            "source_url": source_url,
            "source_date": incident_date,
            "_rekt_id": rekt.get("id"),
            "_rekt_scam_type": scam_type,
        }

    # Primary token_address + additional token_addresses
    addrs_from_fields: set[tuple[str, str | None]] = set()
    ta = rekt.get("token_address") or ""
    if ta:
        addrs_from_fields.add((ta, None))
    for a in rekt.get("token_addresses", []) or []:
        if isinstance(a, dict):
            addr = a.get("address") or a.get("token_address") or ""
            # Sometimes token_addresses items carry a chain hint
            hint = None
            net_name = (a.get("network") or {}).get("name") if isinstance(a.get("network"), dict) else a.get("network")
            if isinstance(net_name, str):
                hint = NETWORK_MAP.get(net_name)
            if addr:
                addrs_from_fields.add((addr, hint))
        elif isinstance(a, str) and a:
            addrs_from_fields.add((a, None))

    for addr, hint_chain in addrs_from_fields:
        if not addr:
            continue
        # Determine chain: use declared from scamNetworks, else infer from format
        if hint_chain:
            chain = hint_chain
        elif addr.startswith("T") and len(addr) == 34:
            chain = "tron"
        elif addr.startswith("0x") and len(addr) == 42:
            # EVM — use declared chain if unique, else 'ethereum' as default
            if len(declared_chains) == 1:
                chain = next(iter(declared_chains))
            elif "ethereum" in declared_chains:
                chain = "ethereum"
            elif declared_chains:
                chain = sorted(declared_chains)[0]
            else:
                chain = "ethereum"  # default EVM
        elif addr.startswith(("1", "3", "bc1")):
            chain = "bitcoin"
        else:
            continue
        records.append(make_record(addr, chain))

    # Additionally: mine HTML description for addresses
    desc = rekt.get("description") or ""
    mined = extract_addresses_from_text(desc)

    # Apply: Tron addresses from description → tron records
    for addr in mined.get("tron", set()):
        records.append(make_record(addr, "tron"))
    for addr in mined.get("bitcoin", set()):
        records.append(make_record(addr, "bitcoin"))
    # EVM addresses from description: use declared chain if single, else skip
    # (to avoid wrong-chain mis-attribution)
    for addr in mined.get("evm_unknown", set()):
        if len(declared_chains) == 1:
            chain = next(iter(declared_chains))
            records.append(make_record(addr, chain))
        elif "ethereum" in declared_chains:
            records.append(make_record(addr, "ethereum"))

    # Dedup within this rekt
    seen = set()
    out = []
    for r in records:
        key = (r["address"], r["chain"])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-dir", type=Path,
        default=Path("data/labels_raw/crypto_rekts"),
    )
    parser.add_argument(
        "--output", type=Path,
        default=Path("data/labels_raw/crypto_rekts_parsed.json"),
    )
    args = parser.parse_args()

    files = sorted(args.input_dir.glob("*.json"))
    print(f"Parsing {len(files)} rekt files from {args.input_dir}", flush=True)

    all_records = []
    chain_counts: dict[str, int] = {}
    tron_hits = 0
    n_skipped = 0

    for f in files:
        try:
            with f.open("r", encoding="utf-8") as fh:
                rekt = json.load(fh)
        except Exception:
            n_skipped += 1
            continue
        recs = parse_one(rekt)
        for r in recs:
            all_records.append(r)
            chain_counts[r["chain"]] = chain_counts.get(r["chain"], 0) + 1
            if r["chain"] == "tron":
                tron_hits += 1

    print(f"\nParsed {len(files) - n_skipped}/{len(files)} files, "
          f"{n_skipped} failed", flush=True)
    print(f"Emitted {len(all_records)} records", flush=True)
    print(f"By chain: {sorted(chain_counts.items(), key=lambda x: -x[1])[:15]}",
          flush=True)
    print(f"Tron hits: {tron_hits}", flush=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(all_records, fh, ensure_ascii=False, separators=(",", ":"))
    print(f"Wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
