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
from openlabels.ofac_attributed import _shape_chain


# Chain inference from address format (base58 Tron is checked before hex
# fallback because both can start with '0x' in the raw feed):
def infer_chain(addr: str) -> str | None:
    """Chain by address form — the inference shared with the OFAC parsers (contract R,
    2026-09-15): base58check for bitcoin/litecoin, then the zcash / dash / bitcoin_gold /
    dogecoin forms, and only then the solana catch-all. Nine OFAC-listed zcash / dash /
    bitcoin_gold addresses used to land under `solana` here (security audit MEDIUM-1)."""
    a = addr.strip()
    if not a:
        return None
    chain = _shape_chain(a)
    return None if chain == "unknown" else chain


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


# --- label type from the SOURCE's own taxonomy (contract R, gate 5, 2026-09-15) ---------
# OpenSanctions carries CryptoWallet entities from very different datasets. Only the
# ones OpenSanctions itself files under the `sanction` topic (or a sanctions-list
# dataset) are designations; the rest are illicit-activity datasets — ransomware
# payment addresses (ransomwhere, 11,186 rows on 2026-09-14), Israeli NBCTF terror-
# financing seizure orders (il_mod_crypto, 578), FBI Lazarus theft notices (33). Typing
# all of them `sanctioned` told a compliance reader «designated by a sanctions authority»
# where the truth was «ransomware payment address».
SANCTION_TOPICS: frozenset[str] = frozenset({"sanction", "sanction.linked", "sanction.counter"})
# dataset-name fragments that are sanctions lists even when a row lacks the topic
SANCTION_DATASET_KEYS: tuple[str, ...] = (
    "ofac",
    "hmt",
    "eu_fsf",
    "un_sc",
    "ch_seco",
    "ca_sema",
    "sanctions",
    "jp_mof",
)
# datasets whose rows are illicit activity of one known kind
DATASET_SUBTYPE: dict[str, str] = {
    "ransomwhere": "ransomware",
    "il_mod_crypto": "terror_financing",
    "us_fbi_lazarus_crypto": "hack",
}
# fallback: the OpenSanctions topic names the kind of illicit activity
TOPIC_SUBTYPE: dict[str, str] = {
    "crime.theft": "theft",
    "crime.terror": "terror_financing",
    "crime.fin": "financial_crime",
    "crime.cyber": "cybercrime",
    "crime.fraud": "fraud",
    "crime.traffick": "trafficking",
    "crime.war": "war_crimes",
    "crime": "crime",
    "wanted": "wanted",
    "debarment": "debarment",
    "export.control": "export_control",
}
# every other dataset fragment that used to mark a row illicit (kept: a row from an
# FBI or Interpol dataset without a mapped topic is still illicit, typed by what we know)
ILLICIT_DATASET_KEYS: tuple[str, ...] = ("il_mod", "fbi_", "interpol")


def classify_wallet(topics: list[str], datasets: list[str]) -> tuple[str, str | None]:
    """(label type, subtype) for a CryptoWallet from ITS source's topics and datasets:
    `sanctioned` only for the `sanction` topic or a sanctions-list dataset; otherwise
    `illicit` with the kind of activity the dataset/topic names; `vasp` (the historical
    non-illicit type here) when nothing marks the wallet illicit."""
    topics = [str(t) for t in (topics or [])]
    datasets = [str(d) for d in (datasets or [])]
    if any(t in SANCTION_TOPICS for t in topics):
        return "sanctioned", None
    if any(k in d.lower() for d in datasets for k in SANCTION_DATASET_KEYS):
        return "sanctioned", None
    for d in datasets:
        if d in DATASET_SUBTYPE:
            return "illicit", DATASET_SUBTYPE[d]
    for t in topics:
        if t in TOPIC_SUBTYPE:
            return "illicit", TOPIC_SUBTYPE[t]
    if any(k in d.lower() for d in datasets for k in ILLICIT_DATASET_KEYS):
        return "illicit", "unspecified"
    return "vasp", None


def wallet_label(name: str, chain: str, topics: list[str], datasets: list[str]) -> dict:
    """The opensanctions label for one wallet, typed by `classify_wallet`, carrying the
    source's datasets and topics in `context` (a consumer can tell an OFAC copy —
    `us_ofac_sdn` — from an EU or UN listing without re-reading the source)."""
    ltype, subtype = classify_wallet(topics, datasets)
    lab: dict = {
        "name": name,
        "type": ltype,
        "source": "opensanctions",
        "chain": chain,
        "context": {"datasets": list(datasets or []), "topics": list(topics or [])},
    }
    if subtype:
        lab["subtype"] = subtype
    return lab


def process_crypto_wallet(
    ent: dict,
    all_entities: dict,
    source_url_base: str,
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

    ltype, _subtype = classify_wallet(topics, datasets)
    sanctioned = ltype == "sanctioned"
    is_illicit = ltype in ("sanctioned", "illicit")

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
            "labels": [wallet_label(wallet_name or holder or "unknown", chain, topics, datasets)],
            "is_illicit": is_illicit,
            "is_exchange": False,
            "is_ai_agent": False,
            "entity_name": holder or wallet_name,
            # `sanctioned` is a category only for a designation; an illicit non-sanction
            # row leaves the entity type to the consumer (its label carries the kind)
            "category": "sanctioned" if sanctioned else (None if is_illicit else "unknown"),
            "sanctioned": sanctioned,
            "sanctions_reference": "; ".join(topics + datasets[:3]) if sanctioned else None,
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
        "--input",
        type=Path,
        required=True,
        help="OpenSanctions targets.nested.json (JSON lines)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/labels_raw/opensanctions_parsed.json"),
    )
    parser.add_argument(
        "--source-url-base",
        default="https://www.opensanctions.org",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"ERROR: {args.input} not found. Run download first.", file=sys.stderr)
        sys.exit(1)

    print(f"Loading {args.input} ({args.input.stat().st_size / 1e9:.2f} GB)...", flush=True)
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
                print(f"  scanned {n_lines:,} lines, {n_wallets} wallets", flush=True)

    print(
        f"\nScanned {n_lines:,} lines, found {n_wallets} CryptoWallet entities, "
        f"{len(all_entities):,} entities total",
        flush=True,
    )

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
