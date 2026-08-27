#!/usr/bin/env python3
"""Parse OpenSanctions targets.nested.json → extract CryptoWallet entities
with attribution, emit raw JSON compatible with merge_to_unified.py.

LICENCE WARNING: OpenSanctions data is CC-BY-NC 4.0. The OUTPUT of this
parser is a derivative of that dataset — do not redistribute it in
commercial contexts, do not commit it to this repository, and do not
include rows with source "opensanctions" in publicly shipped TagPacks.
For a licence-free path to the sanctions core, use
fetch_ofac_primary.py (US Government work, 17 U.S.C. 105).

OpenSanctions schema: each target entity may have `properties.publicKey`
(list of addresses). We want the `CryptoWallet` schema type, which carries
address + holder + jurisdiction + source_refs.

Output record (matches merge_to_unified.py expected schema):
  {
    "address": "0x..." | "T..." | "bc1..." | etc (canonical case:
               EVM/bech32 lowered, base58 preserved byte-for-byte),
    "chain": "ethereum" | "tron" | "bitcoin" | ...,
    "labels": [{"name": entity_name, "type": "sanctioned", "source": "opensanctions", "chain": chain}],
    "is_illicit": True,
    "is_exchange": False,
    "is_ai_agent": False,
    "entity_name": entity_name,
    "category": "sanctioned",
    "sanctioned": True,
    "sanctions_reference": "; ".join(topics ++ dataset_ids),
    "source_url": opensanctions entity URL,
    "source_date": dataset publishedAt,
    "_os_entity_id": original OS entity ID,
    "_os_datasets": source dataset IDs,
    "_os_topics": OS topics,
  }
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from openlabels.address_case import canonical_case


# Chain inference from address format (base58 Tron is checked before hex
# fallback because both can start with '0x' in the raw feed):
def infer_chain(addr: str) -> str | None:
    """Return chain name by address format heuristics."""
    a = addr.strip()
    if not a:
        return None
    # Tron base58check: 'T' + 33 chars from base58 alphabet
    if len(a) == 34 and a[0] == "T" and all(
        c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        for c in a[1:]
    ):
        return "tron"
    # Hex EVM: 0x + 40 hex
    if len(a) == 42 and a.lower().startswith("0x") and all(
        c in "0123456789abcdefABCDEF" for c in a[2:]
    ):
        return "ethereum"  # default EVM; may be Tron/BSC/Base/etc.
    # Bitcoin legacy (P2PKH/P2SH)
    if 26 <= len(a) <= 35 and a[0] in "13" and all(
        c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        for c in a
    ):
        return "bitcoin"
    # Bitcoin bech32
    if a.lower().startswith("bc1"):
        return "bitcoin"
    # Litecoin (ltc1 / L / M / 3)
    if a.lower().startswith("ltc1") or (a[0] in "LM" and 26 <= len(a) <= 35):
        return "litecoin"
    # XRP
    if a[0] == "r" and 25 <= len(a) <= 35:
        return "xrp"
    # Monero (4 / 8 prefix, 95 chars)
    if len(a) in (95, 106) and a[0] in "48":
        return "monero"
    # Solana (base58, 32-44 chars, no prefix constraint)
    if 32 <= len(a) <= 44 and all(
        c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        for c in a
    ):
        return "solana"
    return None


def first_or_none(seq):
    return seq[0] if seq else None


def entity_label(ent: dict) -> str:
    """Pick best human-readable name for an entity."""
    props = ent.get("properties", {})
    for key in ("name", "alias", "weakAlias"):
        v = props.get(key)
        if v:
            return first_or_none(v) or ""
    caption = ent.get("caption")
    if caption:
        return caption
    return ent.get("id", "")


def extract_holder(ent: dict, all_entities: dict) -> str | None:
    """A CryptoWallet points to its holder via the `holder` property
    (list of entity IDs). Resolve and return holder's name."""
    holder_ids = ent.get("properties", {}).get("holder", [])
    if not holder_ids:
        return None
    for hid in holder_ids:
        if isinstance(hid, dict):
            # Nested entity object
            name = entity_label(hid)
            if name:
                return name
        elif isinstance(hid, str) and hid in all_entities:
            name = entity_label(all_entities[hid])
            if name:
                return name
    return None


def process_crypto_wallet(
    ent: dict, all_entities: dict, source_url_base: str,
) -> list[dict]:
    """Emit one record per publicKey of this CryptoWallet entity."""
    props = ent.get("properties", {})
    public_keys = props.get("publicKey", []) or []
    if not public_keys:
        return []

    holder = extract_holder(ent, all_entities)
    wallet_name = entity_label(ent) or holder or ent.get("id", "")
    topics = props.get("topics", []) or []
    datasets = ent.get("datasets", []) or []
    first_seen = ent.get("first_seen", "") or props.get("createdAt", [""])[0]
    last_change = ent.get("last_change", "") or ""

    # Infer illicit from topics / datasets
    illicit_topics = {
        "sanction", "sanction.linked", "crime", "crime.fin", "crime.war",
        "crime.terror", "crime.traffick", "crime.theft", "crime.fraud",
        "crime.cyber", "debarment", "export.control", "wanted",
    }
    is_illicit = any(t in illicit_topics for t in topics) or any(
        d for d in datasets if any(
            k in d.lower() for k in
            ("ofac", "hmt", "eu_fsf", "un_sc", "il_mod", "ch_seco",
             "ca_sema", "sanctions", "fbi_", "interpol")
        )
    )

    records = []
    for pk in public_keys:
        chain = infer_chain(pk)
        if not chain:
            continue
        rec = {
            # Chain-aware: EVM/bech32 lowered, base58 (BTC/LTC/XRP/SOL/XMR/T…)
            # preserved — a blanket `pk.lower() unless T…` once destroyed
            # thousands of sanctioned base58 rows before this policy existed.
            "address": canonical_case(pk),
            "chain": chain,
            "labels": [
                {
                    "name": wallet_name or holder or "unknown",
                    "type": "sanctioned" if is_illicit else "vasp",
                    "source": "opensanctions",
                    "chain": chain,
                }
            ],
            "is_illicit": is_illicit,
            "is_exchange": False,
            "is_ai_agent": False,
            "entity_name": holder or wallet_name,
            "category": "sanctioned" if is_illicit else "unknown",
            "sanctioned": is_illicit,
            "sanctions_reference": "; ".join(topics + datasets[:3]) if is_illicit else None,
            "source_url": f"{source_url_base}/entities/{ent['id']}/",
            "source_date": last_change or first_seen,
            "_os_entity_id": ent["id"],
            "_os_datasets": datasets,
            "_os_topics": topics,
        }
        records.append(rec)
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input", type=Path, required=True,
        help="OpenSanctions targets.nested.json (JSON lines)",
    )
    parser.add_argument(
        "--output", type=Path,
        default=Path("data/labels_raw/opensanctions_parsed.json"),
    )
    parser.add_argument(
        "--source-url-base", default="https://www.opensanctions.org",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"ERROR: {args.input} not found. Run download first.",
              file=sys.stderr)
        sys.exit(1)

    print(f"Loading {args.input} ({args.input.stat().st_size / 1e9:.2f} GB)...",
          flush=True)
    # OpenSanctions targets.nested.json is a JSON LINES file (one entity per
    # line), NOT a single JSON array. Parse line by line.
    wallets = []
    all_entities = {}
    n_lines = 0
    n_wallets = 0

    # First pass: build entity id → entity map (for holder resolution)
    # and collect CryptoWallet entities.
    with args.input.open("r", encoding="utf-8") as fh:
        for line in fh:
            n_lines += 1
            line = line.strip()
            if not line:
                continue
            try:
                ent = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(ent, dict):
                continue
            eid = ent.get("id")
            if eid:
                all_entities[eid] = ent
            if ent.get("schema") == "CryptoWallet":
                wallets.append(ent)
                n_wallets += 1
            if n_lines % 100_000 == 0:
                print(f"  scanned {n_lines:,} lines, {n_wallets} wallets",
                      flush=True)

    print(f"\nScanned {n_lines:,} lines, found {n_wallets} CryptoWallet entities, "
          f"{len(all_entities):,} entities total", flush=True)

    # Second pass: extract records
    records = []
    chain_counts = {}
    illicit_counts = {}
    for ent in wallets:
        recs = process_crypto_wallet(ent, all_entities, args.source_url_base)
        for r in recs:
            records.append(r)
            chain_counts[r["chain"]] = chain_counts.get(r["chain"], 0) + 1
            if r["is_illicit"]:
                illicit_counts[r["chain"]] = illicit_counts.get(r["chain"], 0) + 1

    print(f"\nEmitted {len(records)} records")
    print(f"By chain:   {sorted(chain_counts.items(), key=lambda x: -x[1])}")
    print(f"Illicit by chain: {sorted(illicit_counts.items(), key=lambda x: -x[1])}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, ensure_ascii=False, separators=(",", ":"))
    print(f"\nWrote {args.output}")


if __name__ == "__main__":
    main()
