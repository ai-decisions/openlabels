#!/usr/bin/env python3
"""Merge raw label-source JSON files into a unified label store (v2.1 schema).

Strategy:
  1. Start with an existing unified store (``--base``), or empty.
  2. For each raw file (OFAC, Tronscan, regulator registers, ...), merge
     into the dict keyed by canonical-case address.
  3. On address collision:
     - Union `labels[]` (dedup by (name, source)).
     - `sanctioned=True` dominates on scalar fields.
     - Otherwise first-wins for attribution scalars.
  4. Validate the final dict against the UnifiedLabelRecord v2.1 schema.
  5. Write local output (+ optional build manifest with input/output shas).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path
from typing import get_args

from openlabels.address_case import canonical_case, is_case_destroyed
from openlabels.chains import is_canonical_chain, normalize_chain, resolve_bnb
from openlabels.tron_address import InvalidTronAddress, base58check_to_hex
from openlabels.unified import EntityCategory, LicenseStatus, UnifiedLabelRecord

_VALID_CATEGORIES = frozenset(get_args(EntityCategory))
_VALID_LICENSE_STATUS = frozenset(get_args(LicenseStatus))
_ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

DEFAULT_RAW_DIR = Path("data/labels_raw")


def normalize_key(addr: str, chain: str | None) -> str:
    """Canonical storage key for an address on a given chain.

    Graph and database systems store Tron addresses as `0x<40-hex>` (20-byte EVM-style
    payload, 0x41 mainnet prefix stripped). Public Tron sources publish
    base58check T-addresses. Any T-prefixed base58check address is decoded
    to the canonical hex form; invalid strings fall through to canonical-case.

    EVM hex / bech32 use lowercase as canonical; base58 chains (BTC legacy,
    LTC, XRP, SOL, XMR, …) are case-SENSITIVE and preserved byte-for-byte —
    a blanket `.lower()` fallback once destroyed tens of thousands of
    base58 label rows before this policy existed.
    """
    if chain == "tron" and len(addr) == 34 and addr[0] == "T":
        try:
            return base58check_to_hex(addr)
        except InvalidTronAddress:
            pass
    return canonical_case(addr)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_base(base_path: Path | None) -> dict[str, dict]:
    """Load the existing unified store, or start empty when no base given."""
    if base_path is None:
        return {}
    if not base_path.exists():
        raise FileNotFoundError(f"--base not found: {base_path}")
    with base_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


# A single address token (contract S, S11): letters, digits and the cashaddr colon.
_ADDRESS_TOKEN_RE = re.compile(r"[A-Za-z0-9:]{20,120}")


def _label_context(lab: dict) -> dict:
    ctx = lab.get("context")
    return ctx if isinstance(ctx, dict) else {}


def _label_key(lab: dict) -> tuple:
    # Contract R (2026-09-15): a label that names its page (`context.source_url`) is a
    # fact about THAT page — two OFAC actions on one address with the same title are two
    # labels (a designation and, years later, its removal). Labels without context keep
    # the (name, source, chain) key unchanged.
    return (lab.get("name"), lab.get("source"), lab.get("chain"), _label_context(lab).get("source_url"))


def merge_label_entries(existing: list[dict], incoming: list[dict]) -> list[dict]:
    """Dedupe on (name, source, chain, context.source_url). First-wins on conflict; append new.

    `chain` is part of the key (2026-09-14): OFAC lists GAZA NOW (SDN-47635)
    with one 20-byte payload as an ETH address and as its Tron encoding; both
    normalise to the same hex key, and a (name, source) key silently dropped
    the tron label — the public pack lost the address on Tron. The same name
    and source on two chains are two facts, not a duplicate.
    """
    seen = {_label_key(e) for e in existing}
    out = list(existing)
    for lab in incoming:
        key = _label_key(lab)
        if key not in seen:
            out.append(lab)
            seen.add(key)
    return out


# --- record standing from its labels (contract R / Q2, 2026-09-15) -----------------------
PRESS_RELEASE_SOURCE = "ofac_press_release"
_PR_ACTION_PRIORITY = {"designation": 2, "change": 1, "removal": 0}
_ISO_DAY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
# label types that assert illicit activity on their own (the two-axis model: `mixer`,
# `exchange`, `licit`, `other`, `ai_agent` are entity types, not accusations)
ILLICIT_LABEL_TYPES: frozenset[str] = frozenset(
    {
        "illicit",
        "sanctioned",
        "rugpull",
        "honeypot",
        "phishing",
        "scam",
        "hack",
        "exploit",
        "flash loan attack",
        "access control",
        "reentrancy",
        "oracle issue",
    }
)
# sources whose every label records an illicit incident whatever its type string says
# (crypto_rekts files exploits under `other`)
ILLICIT_ASSERTING_SOURCES: frozenset[str] = frozenset({"crypto_rekts"})


def label_claims_illicit(lab: dict) -> bool:
    ltype = str(lab.get("type") or "").strip().lower()
    return ltype in ILLICIT_LABEL_TYPES or str(lab.get("source") or "") in ILLICIT_ASSERTING_SOURCES


def press_release_status(labels: list[dict]) -> str | None:
    """`listed` | `removed` | None from the DATED press-release labels of a record: the
    latest `context.action_date` decides; on one day designation > change > removal
    (2022-11-08: Tornado Cash deleted and re-designated the same day stays listed).
    Labels without `context` (pre-v7 rows, no page in the cache) do not vote."""
    dated: list[tuple[str, str]] = []
    for lab in labels:
        if lab.get("source") != PRESS_RELEASE_SOURCE:
            continue
        ctx = _label_context(lab)
        action, action_date = ctx.get("action"), ctx.get("action_date")
        # dates compare as strings, so only ISO YYYY-MM-DD may vote (audit 2026-09-15 LOW-1)
        if (
            action in _PR_ACTION_PRIORITY
            and isinstance(action_date, str)
            and _ISO_DAY_RE.fullmatch(action_date)
        ):
            dated.append((action_date, action))
    if not dated:
        return None
    latest = max(d for d, _ in dated)
    net = max((a for d, a in dated if d == latest), key=lambda a: _PR_ACTION_PRIORITY[a])
    return "removed" if net == "removal" else "listed"


def reconcile_press_release_status(rec: dict) -> bool:
    """Record-level `sanctioned` / `is_illicit` / `category` from the record's labels.
    Returns True when the record changed.

    merge_records ORs `sanctioned` (True dominates), which is right for two sources
    that both list an address and wrong for one source that lists it and later delists
    it: 91 store addresses whose LAST OFAC action was a deletion stayed `sanctioned`
    (measured 2026-09-14). A sanctioned-typed label from ANOTHER source keeps the
    record sanctioned whatever the press releases say.
    """
    labels = [lab for lab in (rec.get("labels") or []) if isinstance(lab, dict)]
    status = press_release_status(labels)
    if status is None:
        return False
    other_sanctioned = any(
        str(lab.get("type") or "").strip().lower() == "sanctioned"
        and lab.get("source") != PRESS_RELEASE_SOURCE
        for lab in labels
    )
    changed = False
    if status == "listed" or other_sanctioned:
        if not rec.get("sanctioned"):
            rec["sanctioned"] = True
            changed = True
        if not rec.get("is_illicit"):
            rec["is_illicit"] = True
            changed = True
        if rec.get("category") in (None, "unknown"):
            rec["category"] = "sanctioned"
            changed = True
        return changed
    # removed, and no other source designates it
    if rec.get("sanctioned"):
        rec["sanctioned"] = False
        changed = True
    if rec.get("category") == "sanctioned":
        rec["category"] = None
        changed = True
    # the press releases have spoken as a whole (removed); only OTHER sources' labels vote
    illicit = any(
        label_claims_illicit(lab) for lab in labels if lab.get("source") != PRESS_RELEASE_SOURCE
    )
    if bool(rec.get("is_illicit")) != illicit:
        rec["is_illicit"] = illicit
        changed = True
    return changed


def merge_records(existing: dict, incoming: dict) -> dict:
    """Merge one raw record into the existing entry for the same address.

    Rules:
      - `labels[]`      → union (dedup on (name, source, chain))
      - `sanctioned`    → OR (True dominates)
      - `is_illicit`    → OR
      - `is_exchange`   → OR
      - `is_ai_agent`   → OR
      - scalars (entity_name, category, etc.): first-wins UNLESS the
        incoming record has sanctioned=True and existing doesn't — then
        sanctioned attribution dominates.
    """
    merged = dict(existing)

    merged["labels"] = merge_label_entries(existing.get("labels", []), incoming.get("labels", []))

    for flag in ("sanctioned", "is_illicit", "is_exchange", "is_ai_agent"):
        merged[flag] = bool(existing.get(flag)) or bool(incoming.get(flag))

    scalar_fields = (
        "entity_name",
        "category",
        "jurisdiction",
        "license_id",
        "regulator",
        "license_status",
        "sanctions_reference",
        "source_url",
        "source_date",
    )
    incoming_sanctioned = bool(incoming.get("sanctioned"))
    existing_sanctioned = bool(existing.get("sanctioned"))
    sanctioned_promoted = incoming_sanctioned and not existing_sanctioned

    for f in scalar_fields:
        existing_val = existing.get(f)
        incoming_val = incoming.get(f)
        if sanctioned_promoted and incoming_val is not None:
            merged[f] = incoming_val
        elif existing_val in (None, "", False) and incoming_val is not None:
            merged[f] = incoming_val

    # Preserve any _raw fields from both sides.
    for k, v in incoming.items():
        if k.startswith("_") and k not in merged:
            merged[k] = v

    return merged


def sanitize_incoming(rec: dict) -> tuple[dict, dict]:
    """Schema-align an INCOMING raw record without inventing attribution.

    Out-of-enum `category`/`license_status` are stashed into `_*_raw` fields
    (downstream consumers can categorise via labels[].type, so nothing is
    lost); a `source_date` carrying a time component is truncated to its date
    with the original preserved. Base records are never touched here —
    pre-existing schema failures in a base store are a separate concern.

    Returns (record, counters_delta).
    """
    delta = {
        "category_stashed": 0,
        "license_status_stashed": 0,
        "date_truncated": 0,
        "date_invalid_nulled": 0,
    }
    cat = rec.get("category")
    if cat is not None and cat not in _VALID_CATEGORIES:
        rec["_category_raw"] = cat
        rec["category"] = None
        delta["category_stashed"] = 1
    lic = rec.get("license_status")
    if lic is not None and lic not in _VALID_LICENSE_STATUS:
        rec["_license_status_raw"] = lic
        rec["license_status"] = None
        delta["license_status_stashed"] = 1
    sd = rec.get("source_date")
    if isinstance(sd, str):
        s = sd.strip()
        if len(s) > 10 and _ISO_DATE_RE.fullmatch(s[:10]):
            rec["_source_date_raw"] = sd
            rec["source_date"] = s[:10]
            delta["date_truncated"] = 1
        elif not _ISO_DATE_RE.fullmatch(s):
            # empty or partial ("", "2009-03") — schema wants a date or None
            rec["_source_date_raw"] = sd
            rec["source_date"] = None
            delta["date_invalid_nulled"] = 1
    return rec, delta


def load_raw_file(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Raw sources might be keyed by address; unwrap to list
        out = []
        for addr, rec in data.items():
            rec = dict(rec)
            rec.setdefault("address", addr)
            out.append(rec)
        return out
    raise TypeError(f"Unexpected raw format in {path}: {type(data).__name__}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=DEFAULT_RAW_DIR,
        help="Directory with *.json raw source files",
    )
    parser.add_argument(
        "--base",
        type=Path,
        default=None,
        help="Existing unified label store to merge onto (omit to start empty)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / f"unified_labels_v2_{date.today().isoformat()}.json",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip Pydantic validation of every output record (fast path)",
    )
    parser.add_argument(
        "--inputs",
        nargs="*",
        default=None,
        help="Explicit raw file names (relative to --raw-dir). Canonical "
        "builds MUST pass this: the raw dir also holds non-label files "
        "(NDJSON FtM dumps, GitHub API listings) that json.load cannot "
        "merge — a bare glob is not a reproducible input set.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Write a build manifest JSON (base+inputs shas, per-file "
        "counts, merge summary, output sha) to this path",
    )
    args = parser.parse_args()

    # Load the base unified store (or start empty)
    current = load_base(args.base)
    base_records = len(current)
    print(f"Loaded base unified store: {base_records} records")

    # Normalize: ensure each record has 'address' key
    for addr, rec in current.items():
        if isinstance(rec, dict):
            rec.setdefault("address", addr)

    # Process each raw file
    if args.inputs:
        raw_files = [args.raw_dir / name for name in args.inputs]
        missing = [str(p) for p in raw_files if not p.exists()]
        if missing:
            raise FileNotFoundError(f"--inputs not found: {missing}")
    else:
        raw_files = sorted(args.raw_dir.glob("*.json"))
    print(f"Raw sources: {[p.name for p in raw_files]}")

    added = 0
    merged_count = 0
    skipped_no_address = 0
    refused_destroyed = 0
    refused_synthetic = 0
    sanitized = Counter()
    inputs_meta: list[dict] = []
    for raw_file in raw_files:
        recs = load_raw_file(raw_file)
        print(f"\n  {raw_file.name}: {len(recs)} records")
        file_skipped = 0
        file_destroyed = 0
        file_synthetic = 0
        file_bad_address = 0
        file_unknown_chain = 0
        file_unknown_label_chain = 0
        bad_examples: list[str] = []
        unknown_chain_examples: list[str] = []
        for rec in recs:
            raw_addr = rec.get("address")
            if not raw_addr:
                # Not a label row (e.g. crypto_rekts_index.json is a GitHub
                # API file listing). Skipped LOUDLY, never silently dropped.
                file_skipped += 1
                continue
            # Canonical chain spelling before anything keys on it (xdai → gnosis,
            # eth → ethereum, Avax → avalanche_c): two spellings of one chain were
            # two keys nobody queried together (contract P, 2026-09-14).
            # Contract S (S7/S11, 2026-09-14): a chain outside the allow-list and an
            # address that is not a single token are refused LOUDLY — a label keyed under
            # a misspelt chain is served to nobody, a junk key never matches a query.
            if not _ADDRESS_TOKEN_RE.fullmatch(str(raw_addr).strip()):
                file_bad_address += 1
                if len(bad_examples) < 5:
                    bad_examples.append(str(raw_addr)[:60])
                continue
            rec["chain"] = resolve_bnb(normalize_chain(rec.get("chain")), raw_addr)
            if not is_canonical_chain(rec["chain"]):
                file_unknown_chain += 1
                if len(unknown_chain_examples) < 5:
                    unknown_chain_examples.append(str(rec.get("chain"))[:40])
                continue
            kept_labels = []
            for lab in rec.get("labels") or []:
                if isinstance(lab, dict) and lab.get("chain") is not None:
                    lab["chain"] = resolve_bnb(normalize_chain(lab.get("chain")), raw_addr)
                    if not is_canonical_chain(lab["chain"]):
                        file_unknown_label_chain += 1
                        continue
                kept_labels.append(lab)
            if rec.get("labels") is not None:
                rec["labels"] = kept_labels
            addr = normalize_key(raw_addr, rec.get("chain"))
            if is_case_destroyed(addr, rec.get("chain")):
                # Ingest case gate: a lowercased base58 address is a wound
                # from a broken upstream parser, not a label. Refused here —
                # measured: virtually every destroyed row already sits in
                # the base under its recovered mixed-case twin.
                file_destroyed += 1
                continue
            if "::" in addr:
                # Synthetic entity key (e.g. ch_finma::license_id::CHE-…):
                # a VASP-registry row with NO on-chain address. unified is
                # address-keyed and lookups go by (chain, address) — such a
                # key is unreachable dead weight; the entity itself already
                # lives in the VASP directory artefact.
                file_synthetic += 1
                continue
            rec, san_delta = sanitize_incoming(rec)
            for k, v in san_delta.items():
                sanitized[k] += v
            rec["address"] = addr
            if addr in current:
                current[addr] = merge_records(current[addr], rec)
                merged_count += 1
            else:
                current[addr] = rec
                added += 1
        if file_skipped:
            print(f"    skipped (no 'address' field): {file_skipped}")
        if file_bad_address:
            print(
                f"    SKIPPED LOUDLY (address is not a single token): {file_bad_address} e.g. {bad_examples}"
            )
        if file_unknown_chain:
            print(
                f"    SKIPPED LOUDLY (chain outside the allow-list): {file_unknown_chain} e.g. {unknown_chain_examples}"
            )
        if file_unknown_label_chain:
            print(
                f"    labels DROPPED LOUDLY (label chain outside the allow-list): {file_unknown_label_chain}"
            )
        if file_destroyed:
            print(f"    REFUSED (case-destroyed base58): {file_destroyed}")
        if file_synthetic:
            print(f"    REFUSED (synthetic non-address key): {file_synthetic}")
        skipped_no_address += file_skipped
        refused_destroyed += file_destroyed
        refused_synthetic += file_synthetic
        inputs_meta.append(
            {
                "name": raw_file.name,
                "sha256": _sha256(raw_file),
                "records": len(recs),
                "skipped_no_address": file_skipped,
                "skipped_bad_address": file_bad_address,
                "skipped_unknown_chain": file_unknown_chain,
                "dropped_unknown_label_chain": file_unknown_label_chain,
                "refused_case_destroyed": file_destroyed,
                "refused_synthetic_key": file_synthetic,
            }
        )

    # Contract R (Q2): a record's standing follows its dated press-release labels — a
    # later OFAC removal ends a listing that merge_records' OR would keep forever.
    reconciled = sum(
        1 for rec in current.values() if isinstance(rec, dict) and reconcile_press_release_status(rec)
    )

    print("\nMerge summary:")
    print(f"  Existing entries:   {len(current) - added}")
    print(f"  PR status reconciled: {reconciled}")
    print(f"  Newly added:        {added}")
    print(f"  Collision-merged:   {merged_count}")
    print(f"  Skipped no-address: {skipped_no_address}")
    print(f"  Refused destroyed:  {refused_destroyed}")
    print(f"  Refused synthetic:  {refused_synthetic}")
    print(f"  Sanitized incoming: {dict(sanitized)}")
    print(f"  Total output size:  {len(current)}")

    # Validate everything (skip if requested; useful for debugging)
    errs: int | None = None
    if not args.skip_validation:
        print("\nValidating against UnifiedLabelRecord v2.1 schema...")
        errs = 0
        for addr, rec in current.items():
            try:
                UnifiedLabelRecord.model_validate(rec)
            except Exception as e:
                errs += 1
                if errs <= 3:
                    print(f"  ERR {addr}: {str(e).splitlines()[0][:120]}")
        print(f"Validated: {len(current)-errs}/{len(current)}")
        print(f"Validation errors: {errs} (pre-existing + new)")

    # Tron-chain subset count for contract PASS signal
    tron_records = [r for r in current.values() if isinstance(r, dict) and r.get("chain") == "tron"]
    tron_sanctioned = [r for r in tron_records if r.get("sanctioned")]
    tron_exchange = [r for r in tron_records if r.get("is_exchange")]
    tron_entities = Counter(r.get("entity_name") for r in tron_records if r.get("entity_name"))

    print("\nTron subset in merged file:")
    print(f"  Total Tron records:   {len(tron_records)}")
    print(f"  Sanctioned (illicit): {len(tron_sanctioned)}")
    print(f"  Exchange (VASP):      {len(tron_exchange)}")
    print(f"  Distinct entities:    {len(tron_entities)}")
    print("  Top entities:")
    for e, n in tron_entities.most_common(10):
        print(f"    {n:3d}  {e}")

    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(current, fh, ensure_ascii=False)
    size_mb = args.output.stat().st_size / 1024 / 1024
    print(f"\nOutput: {args.output} ({size_mb:.1f} MiB)")

    if args.manifest:
        manifest = {
            "artefact": args.output.name,
            "built_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            "command": " ".join(sys.argv),
            "base": (
                {
                    "file": args.base.name,
                    "sha256": _sha256(args.base),
                    "records": base_records,
                }
                if args.base
                else {"file": None, "records": 0}
            ),
            "inputs": inputs_meta,
            "merge": {
                "added": added,
                "collision_merged": merged_count,
                "skipped_no_address": skipped_no_address,
                "refused_case_destroyed": refused_destroyed,
                "refused_synthetic_key": refused_synthetic,
                "sanitized_incoming": dict(sanitized),
                "total": len(current),
            },
            "validation_errors": errs,
            "output_sha256": _sha256(args.output),
        }
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        with args.manifest.open("w", encoding="utf-8") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=1)
        print(f"Manifest: {args.manifest}")


if __name__ == "__main__":
    main()
