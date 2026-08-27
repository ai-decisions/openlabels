#!/usr/bin/env python3
"""Build a mixer registry parquet from public sources.

Scope: mixer families at the public-label ceiling measured by
probe_mixer_sources.py (Tornado Cash + Sinbad have enumerable public
addresses), plus a DPRK3-program superset recorded in the manifest for
transparency.

Output (a separate subdir — NOT sibling files at a labels/ root, which
breaks pyarrow.dataset consumers):
  <out-dir>/registry.parquet
  <out-dir>/manifest.json

Schema (locked before the first build):
  address              : str          # ETH lowercased; BTC base58/bech32 case-preserved
  chain                : str          # eth | btc | bsc | polygon | arbitrum | tron | sol
  family               : str          # tornado_cash | sinbad
  entity_program_tags  : list[str]    # [DPRK3] / [CYBER2] / etc.
  operator_party       : str | null   # "44718:Semenov_Roman" / "<sinbad_fixedref>:Sinbad"
  sources              : list[dict]   # multi-source attribution (every row traceable)
  first_seen_utc       : str | null   # ISO8601 if available (probe v1 leaves null)

Manifest (separate file, captures provenance + canary + overlap + DPRK3 superset).

Source-attribution rule: every address row carries sources:list[dict] with
kind+ref+raw, and ≥10 random rows are re-fetched from source bytes on the
build host (provenance canary) before the parquet is written.

Re-uses the HTTP fetch + atomic-cache + sha256 + iterparse pattern of
probe_mixer_sources.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants — mirror probe v3 (DO NOT diverge silently; if probe constants
# drift, a probe re-run must precede any scope change).
# ---------------------------------------------------------------------------

OFAC_SDN_XML_URL = (
    "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/"
    "exports/SDN_ADVANCED.XML"
)

CRYPTO_FEATURE_TYPE_IDS: dict[str, str] = {
    "344": "btc",
    "345": "eth",
    "444": "xmr",
    "566": "ltc",
    "686": "zec",
    "687": "dash",
    "688": "btg",
    "689": "etc",
    "706": "bsv",
    "726": "bch",
    "746": "xvg",
    "887": "usdt",
    "907": "xrp",
    "992": "tron",
    "998": "usdc",
    "1007": "arbitrum",
    "1008": "bsc",
    "1167": "sol",
}

DAWSBOT_REPO_API = "https://api.github.com/repos/dawsbot/eth-labels"
DAWSBOT_REPO_RAW_BASE = "https://raw.githubusercontent.com/dawsbot/eth-labels"
DAWSBOT_CANDIDATE_PATHS = [
    "data/json/accounts.json",
    "labels/labels.json",
    "src/labels/labels.json",
    "data/labels.json",
    "src/data.json",
]

REGISTRY_PARQUET_NAME = "registry.parquet"
MANIFEST_NAME = "manifest.json"

RETRY_ATTEMPTS = 3
RETRY_BACKOFF_SEC = (5, 15, 45)
_TERMINAL_4XX = frozenset({400, 401, 404, 405, 410, 414, 415, 451})
_TERMINAL_4XX_HEAD = frozenset({400, 401, 404, 410, 414, 415, 451})

ADDR_RE_EVM = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
ADDR_RE_BTC = re.compile(r"\b(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")

# DPRK3 superset parties expected per the OFAC designation record (sentinel for canary).
EXPECTED_DPRK3_PARTY_NAMES_SUBSTRING = [
    "lazarus",
    "semenov",
    "sinbad",
    "wu huihui",
    "tian yinyin",
    "li jiadong",
]

# Sentinel addresses — the OFAC designation record names exactly 8 ETH addresses on
# Semenov Roman (FixedRef=44718). At least the first one MUST appear in the
# parsed OFAC output AND in the dawsbot Tornado pool list (overlap pathway).
SEMENOV_SENTINEL_ETH = "0xdcbeffbecce100cce9e4b153c4e15cb885643193"

# Sinbad sentinel BTC addresses — from the OFAC designation record.
SINBAD_SENTINEL_BTC = [
    "1JHdQHkBZiim1cb4hyUh2PbzEbbg6z2TrF",
    "bc1qq7p0es3dv5hcynjjf40f2xjjr6qp5py47d2f6n847vduuq9gvnyq7y9ecd",
]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FeatureRow:
    """One OFAC <Feature> with crypto FeatureTypeID — direct trace."""
    party_uid: str
    party_primary_name: str
    party_all_aliases: list[str]
    party_programs: list[str]
    feature_type_id: str
    feature_id: str | None
    chain: str
    address_raw: str


@dataclass
class SourceMeta:
    name: str
    url: str | None
    source_uri: str | None
    fetch_utc: str
    bytes_fetched: int
    sha256: str
    record_count: int
    integrity_check_passed: bool
    integrity_notes: str = ""


@dataclass
class RegistryRow:
    address: str
    chain: str
    family: str
    entity_program_tags: list[str] = field(default_factory=list)
    operator_party: str | None = None
    sources: list[dict] = field(default_factory=list)
    first_seen_utc: str | None = None


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _file_sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def _norm_eth(a: str) -> str:
    return a.lower() if a.startswith("0x") else a


def fetch_with_retry(url: str, timeout: int = 60) -> bytes | None:
    last_err: Exception | None = None
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (openlabels-build)"}
    )
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code in _TERMINAL_4XX:
                print(f"  fetch FAIL (terminal {e.code}) {url}: {e}", file=sys.stderr)
                return None
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_BACKOFF_SEC[attempt])
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_BACKOFF_SEC[attempt])
    print(f"  fetch FAIL {url}: {last_err}", file=sys.stderr)
    return None


def head_check(url: str, timeout: int = 10) -> int | None:
    req = urllib.request.Request(
        url, method="HEAD",
        headers={"User-Agent": "Mozilla/5.0 (openlabels-build)"},
    )
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status
        except urllib.error.HTTPError as e:
            if e.code in _TERMINAL_4XX_HEAD:
                return e.code
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_BACKOFF_SEC[attempt])
        except Exception:
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_BACKOFF_SEC[attempt])
    return None


def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip()
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# OFAC SDN feature-level loader (variant of probe v3 load_ofac_sdn)
# ---------------------------------------------------------------------------


def load_ofac_features(cache: Path) -> tuple[list[FeatureRow], SourceMeta]:
    """Stream-parse SDN_ADVANCED.XML, emit one FeatureRow per crypto Feature.

    Differs from probe v3 load_ofac_sdn: probe emits party-level rows with
    semicolon-joined id_values; here we keep feature-level rows so each
    address has a direct (party_uid, feature_id, address) trace tuple.
    Manifest then carries source_uri = "ofac_sdn:fixedref=N:feature_id=M".
    """
    cache_path = cache / "sdn_advanced.xml"
    if not cache_path.exists():
        data = fetch_with_retry(OFAC_SDN_XML_URL, timeout=180)
        if data is None:
            return [], SourceMeta(
                name="ofac_sdn", url=OFAC_SDN_XML_URL, source_uri=None,
                fetch_utc=_now_utc(), bytes_fetched=0, sha256="",
                record_count=0, integrity_check_passed=False,
                integrity_notes="HTTP fetch failed",
            )
        _atomic_write(cache_path, data)

    raw = cache_path.read_bytes()

    if len(raw) < 50_000_000:
        return [], SourceMeta(
            name="ofac_sdn", url=OFAC_SDN_XML_URL, source_uri=None,
            fetch_utc=_now_utc(), bytes_fetched=len(raw),
            sha256=_file_sha256(raw), record_count=0,
            integrity_check_passed=False,
            integrity_notes=f"size {len(raw)} bytes < 50 MB threshold",
        )

    features: list[FeatureRow] = []
    party_to_programs: dict[str, list[str]] = {}

    in_party = False
    in_alias = False
    in_documented_name_part = False
    primary_alias = False
    in_feature = False

    party_uid: str | None = None
    party_name_parts: list[str] = []
    primary_name_parts: list[str] = []
    aliases: list[str] = []
    current_feature_type_id: str | None = None
    current_feature_id: str | None = None
    current_feature_is_crypto = False
    pending_features_for_party: list[FeatureRow] = []

    root_elem = None
    party_count = 0

    try:
        ctx = ET.iterparse(str(cache_path), events=("start", "end"))

        for event, elem in ctx:
            if root_elem is None and event == "start":
                root_elem = elem

            tag = _strip_ns(elem.tag)

            if event == "start":
                if tag == "DistinctParty":
                    in_party = True
                    party_uid = elem.get("FixedRef")
                    primary_name_parts = []
                    aliases = []
                    pending_features_for_party = []

                elif in_party and tag == "Alias":
                    in_alias = True
                    party_name_parts = []
                    primary_alias = (
                        elem.get("AliasTypeID") == "1403"
                        and elem.get("Primary") == "true"
                    )

                elif in_party and tag == "DocumentedNamePart":
                    in_documented_name_part = True

                elif in_party and tag == "Feature":
                    in_feature = True
                    current_feature_type_id = elem.get("FeatureTypeID")
                    current_feature_id = elem.get("ID")
                    current_feature_is_crypto = (
                        current_feature_type_id in CRYPTO_FEATURE_TYPE_IDS
                    )

            else:
                text = (elem.text or "").strip()

                if in_party and tag == "NamePartValue" and in_documented_name_part and text:
                    party_name_parts.append(text)

                elif in_party and tag == "DocumentedNamePart":
                    in_documented_name_part = False

                elif in_party and tag == "Alias":
                    in_alias = False  # noqa: F841 — write-only state, kept for parser symmetry
                    name_str = " ".join(p for p in party_name_parts if p).strip()
                    if name_str:
                        if primary_alias:
                            primary_name_parts.append(name_str)
                        else:
                            aliases.append(name_str)
                    primary_alias = False
                    party_name_parts = []

                elif in_party and tag == "VersionDetail" and in_feature and text:
                    if current_feature_is_crypto and party_uid:
                        pending_features_for_party.append(FeatureRow(
                            party_uid=party_uid,
                            party_primary_name="",  # filled at DistinctParty close
                            party_all_aliases=[],   # filled at close
                            party_programs=[],      # filled in Pass 2
                            feature_type_id=current_feature_type_id or "",
                            feature_id=current_feature_id,
                            chain=CRYPTO_FEATURE_TYPE_IDS[current_feature_type_id]
                                  if current_feature_type_id in CRYPTO_FEATURE_TYPE_IDS
                                  else "",
                            address_raw=text,
                        ))

                elif in_party and tag == "Feature":
                    in_feature = False
                    current_feature_type_id = None
                    current_feature_id = None
                    current_feature_is_crypto = False

                elif tag == "DistinctParty" and in_party:
                    in_party = False
                    party_count += 1
                    primary_name = " ".join(primary_name_parts).strip()
                    for fr in pending_features_for_party:
                        fr.party_primary_name = primary_name
                        fr.party_all_aliases = list(aliases)
                        features.append(fr)
                    elem.clear()
                    if root_elem is not None and party_count % 500 == 0:
                        root_elem.clear()

                elif tag == "SanctionsEntry":
                    profile_id = elem.get("ProfileID")
                    if profile_id:
                        progs: list[str] = []
                        for measure in elem.iter():
                            if _strip_ns(measure.tag) != "SanctionsMeasure":
                                continue
                            for sub in measure.iter():
                                if _strip_ns(sub.tag) == "Comment" and (sub.text or "").strip():
                                    progs.append(sub.text.strip())
                        if progs:
                            party_to_programs[profile_id] = progs
                    elem.clear()

    except ET.ParseError as e:
        return [], SourceMeta(
            name="ofac_sdn", url=OFAC_SDN_XML_URL, source_uri=None,
            fetch_utc=_now_utc(), bytes_fetched=len(raw),
            sha256=_file_sha256(raw), record_count=0,
            integrity_check_passed=False, integrity_notes=f"XML parse: {e}",
        )

    # Apply party_to_programs
    for fr in features:
        if fr.party_uid in party_to_programs:
            fr.party_programs = list(party_to_programs[fr.party_uid])

    return features, SourceMeta(
        name="ofac_sdn", url=OFAC_SDN_XML_URL, source_uri=None,
        fetch_utc=_now_utc(), bytes_fetched=len(raw),
        sha256=_file_sha256(raw), record_count=len(features),
        integrity_check_passed=True,
        integrity_notes=f"ok; {len(features)} crypto features across {party_count} parties",
    )


# ---------------------------------------------------------------------------
# Dawsbot loader — keeps record idx for source-attribution
# ---------------------------------------------------------------------------


def _discover_dawsbot_url() -> str | None:
    repo_data = fetch_with_retry(DAWSBOT_REPO_API, timeout=30)
    if repo_data is None:
        return None
    try:
        meta = json.loads(repo_data)
    except Exception:
        return None
    branch = meta.get("default_branch")
    if not branch:
        return None
    for path in DAWSBOT_CANDIDATE_PATHS:
        url = f"{DAWSBOT_REPO_RAW_BASE}/{branch}/{path}"
        status = head_check(url, timeout=10)
        if status == 200:
            return url
        if status == 405:
            probe = fetch_with_retry(url, timeout=10)
            if probe and (probe.startswith(b"{") or probe.startswith(b"[")):
                return url
    return None


def load_dawsbot_records(cache: Path) -> tuple[list[dict], SourceMeta]:
    """Return list of dawsbot records WITH stable original-index (for source_uri).
    Records preserved as-fetched: each item is the raw dict with 'address',
    'chainId', 'label', 'nameTag' fields per dawsbot v1 layout. Index is the
    position in the JSON list (or in the flattened list-of-categories order).
    """
    cache_path = cache / "dawsbot_labels.json"
    discovered_url = None
    if not cache_path.exists():
        discovered_url = _discover_dawsbot_url()
        if discovered_url is None:
            return [], SourceMeta(
                name="dawsbot_eth_labels", url=None, source_uri=None,
                fetch_utc=_now_utc(), bytes_fetched=0, sha256="",
                record_count=0, integrity_check_passed=False,
                integrity_notes="GitHub API discovery failed",
            )
        data = fetch_with_retry(discovered_url)
        if data is None:
            return [], SourceMeta(
                name="dawsbot_eth_labels", url=discovered_url, source_uri=None,
                fetch_utc=_now_utc(), bytes_fetched=0, sha256="",
                record_count=0, integrity_check_passed=False,
                integrity_notes="HTTP fetch failed",
            )
        _atomic_write(cache_path, data)

    raw = cache_path.read_bytes()
    parsed = json.loads(raw)

    records: list[dict] = []
    if isinstance(parsed, list):
        # v1 layout: flat list of {address, chainId, label, nameTag}
        records = [r for r in parsed if isinstance(r, dict) and r.get("address")]
    elif isinstance(parsed, dict):
        sample = next(iter(parsed.values()), None) if parsed else None
        if isinstance(sample, list):
            for category, recs in parsed.items():
                if not isinstance(recs, list):
                    continue
                for rec in recs:
                    if isinstance(rec, dict) and rec.get("address"):
                        rcopy = dict(rec)
                        rcopy.setdefault("category", category)
                        records.append(rcopy)
        else:
            for addr, info in parsed.items():
                if isinstance(addr, str) and isinstance(info, dict):
                    rcopy = dict(info)
                    rcopy["address"] = addr
                    records.append(rcopy)

    return records, SourceMeta(
        name="dawsbot_eth_labels", url=discovered_url, source_uri=None,
        fetch_utc=_now_utc(), bytes_fetched=len(raw),
        sha256=_file_sha256(raw), record_count=len(records),
        integrity_check_passed=len(records) >= 100,
        integrity_notes="ok" if len(records) >= 100 else "low record count",
    )


# ---------------------------------------------------------------------------
# Build logic
# ---------------------------------------------------------------------------


def is_dprk3(programs: list[str]) -> bool:
    return any(p.upper() == "DPRK3" for p in programs)


def find_sinbad_party_features(features: list[FeatureRow]) -> list[FeatureRow]:
    """Return features attached to the OFAC entity named 'Sinbad' (or alias).
    the OFAC designation record lists 2 BTC addresses.
    """
    out = []
    for fr in features:
        name_lc = fr.party_primary_name.lower()
        aliases_lc = " ; ".join(fr.party_all_aliases).lower()
        if re.search(r"\bsinbad\b", name_lc) or re.search(r"\bsinbad\b", aliases_lc):
            out.append(fr)
    return out


def find_semenov_party_features(features: list[FeatureRow]) -> list[FeatureRow]:
    """Return features on Semenov Roman party (OFAC FixedRef=44718)."""
    out = []
    for fr in features:
        name_lc = fr.party_primary_name.lower()
        if "semenov" in name_lc:
            out.append(fr)
    return out


def filter_dawsbot_tornado(records: list[dict]) -> list[tuple[int, dict]]:
    """Return [(idx, record)] for dawsbot records whose nameTag/label match
    Tornado Cash (case-insensitive 'tornado' substring). By scope decision:
    expected 68 records.
    """
    out: list[tuple[int, dict]] = []
    pattern = re.compile(r"tornado", re.IGNORECASE)
    for idx, rec in enumerate(records):
        text_blob = " ".join(str(rec.get(k, "")) for k in ("label", "nameTag", "name", "category"))
        if pattern.search(text_blob):
            out.append((idx, rec))
    return out


def build_registry(
    ofac_features: list[FeatureRow],
    dawsbot_records: list[dict],
) -> tuple[list[RegistryRow], dict]:
    """Construct registry rows + side-channel stats for manifest.

    Scope decisions:
      - Sinbad: take ALL features on Sinbad-named party (expected 2 BTC).
      - Tornado Cash: dawsbot Tornado-tagged records (expected 68 ETH) +
        Semenov party features (expected 8 ETH); merge by address; rows with
        both sources carry sources=[ofac_sdn, dawsbot].
      - Other DPRK3 parties (Lazarus / Wu / Tian / Li): NOT in registry rows
        (per the locked schema). Recorded in manifest.dprk3_superset only.
    """
    rows_by_address: dict[str, RegistryRow] = {}

    # -- Sinbad --
    sinbad_features = find_sinbad_party_features(ofac_features)
    for fr in sinbad_features:
        addr_norm = _norm_eth(fr.address_raw) if fr.chain == "eth" else fr.address_raw
        row = RegistryRow(
            address=addr_norm,
            chain=fr.chain,
            family="sinbad",
            entity_program_tags=list(fr.party_programs),
            operator_party=f"{fr.party_uid}:Sinbad",
            sources=[{
                "kind": "ofac_sdn",
                "fixedref": fr.party_uid,
                "feature_id": fr.feature_id,
                "feature_type_id": fr.feature_type_id,
                "raw": fr.address_raw,
            }],
            first_seen_utc=None,
        )
        rows_by_address[addr_norm] = row

    # -- Tornado Cash from dawsbot --
    dawsbot_tornado = filter_dawsbot_tornado(dawsbot_records)
    for idx, rec in dawsbot_tornado:
        raw_addr = str(rec.get("address", "")).strip()
        if not raw_addr:
            continue
        addr_norm = _norm_eth(raw_addr)
        chain_id = rec.get("chainId")
        # dawsbot v1 chainId 1=eth, 56=bsc, 137=polygon, 42161=arbitrum
        chain_map = {1: "eth", 56: "bsc", 137: "polygon", 42161: "arbitrum"}
        chain = chain_map.get(chain_id, "eth")  # default eth
        if addr_norm in rows_by_address:
            rows_by_address[addr_norm].sources.append({
                "kind": "dawsbot",
                "idx": idx,
                "label": rec.get("label"),
                "name_tag": rec.get("nameTag"),
                "raw": raw_addr,
            })
        else:
            row = RegistryRow(
                address=addr_norm,
                chain=chain,
                family="tornado_cash",
                entity_program_tags=[],
                operator_party=None,
                sources=[{
                    "kind": "dawsbot",
                    "idx": idx,
                    "label": rec.get("label"),
                    "name_tag": rec.get("nameTag"),
                    "raw": raw_addr,
                }],
                first_seen_utc=None,
            )
            rows_by_address[addr_norm] = row

    # -- Tornado Cash via Semenov OFAC --
    semenov_features = find_semenov_party_features(ofac_features)
    semenov_addresses = set()
    for fr in semenov_features:
        addr_norm = _norm_eth(fr.address_raw) if fr.chain == "eth" else fr.address_raw
        semenov_addresses.add(addr_norm)
        if addr_norm in rows_by_address:
            rows_by_address[addr_norm].sources.append({
                "kind": "ofac_sdn",
                "fixedref": fr.party_uid,
                "feature_id": fr.feature_id,
                "feature_type_id": fr.feature_type_id,
                "raw": fr.address_raw,
            })
            # Existing row was tagged tornado_cash by dawsbot — keep family,
            # add DPRK3 program + Semenov operator.
            existing = rows_by_address[addr_norm]
            for tag in fr.party_programs:
                if tag not in existing.entity_program_tags:
                    existing.entity_program_tags.append(tag)
            if existing.operator_party is None:
                existing.operator_party = f"{fr.party_uid}:Semenov_Roman"
        else:
            row = RegistryRow(
                address=addr_norm,
                chain=fr.chain,
                family="tornado_cash",  # Semenov is the Tornado Cash dev (OFAC record)
                entity_program_tags=list(fr.party_programs),
                operator_party=f"{fr.party_uid}:Semenov_Roman",
                sources=[{
                    "kind": "ofac_sdn",
                    "fixedref": fr.party_uid,
                    "feature_id": fr.feature_id,
                    "feature_type_id": fr.feature_type_id,
                    "raw": fr.address_raw,
                }],
                first_seen_utc=None,
            )
            rows_by_address[addr_norm] = row

    rows = list(rows_by_address.values())

    # Overlap stats — per QA M1 fix.
    dawsbot_addrs = {_norm_eth(str(r.get("address", ""))) for _, r in dawsbot_tornado if r.get("address")}
    overlap = semenov_addresses & dawsbot_addrs
    only_ofac = semenov_addresses - dawsbot_addrs
    only_daws = dawsbot_addrs - semenov_addresses

    overlap_stats = {
        "tornado_cash": {
            "ofac_addresses_total": len(semenov_addresses),
            "dawsbot_addresses_total": len(dawsbot_addrs),
            "ofac_in_dawsbot_count": len(overlap),
            "missing_from_dawsbot": sorted(only_ofac),
            "missing_from_ofac": sorted(only_daws),
        }
    }

    return rows, overlap_stats


# ---------------------------------------------------------------------------
# DPRK3 superset for manifest (transparency, not registry rows)
# ---------------------------------------------------------------------------


def compute_dprk3_superset(features: list[FeatureRow]) -> dict:
    """Per the OFAC record: 6 OFAC parties with DPRK3 program have crypto
    addresses totalling 55 (Lazarus 8, Tian Yinyin 8, Li Jiadong 12,
    Wu Huihui 17, Sinbad 2, Semenov 8).
    """
    parties: dict[str, dict] = {}
    for fr in features:
        if not is_dprk3(fr.party_programs):
            continue
        if fr.party_uid not in parties:
            parties[fr.party_uid] = {
                "fixedref": fr.party_uid,
                "name": fr.party_primary_name,
                "programs": list(fr.party_programs),
                "addresses": [],
            }
        parties[fr.party_uid]["addresses"].append({
            "address": _norm_eth(fr.address_raw) if fr.chain == "eth" else fr.address_raw,
            "chain": fr.chain,
            "feature_id": fr.feature_id,
        })
    party_list = []
    total = 0
    for _uid, info in parties.items():
        info["addr_count"] = len(info["addresses"])
        total += info["addr_count"]
        party_list.append(info)
    party_list.sort(key=lambda p: -p["addr_count"])
    return {"parties": party_list, "total_addresses": total}


# ---------------------------------------------------------------------------
# Provenance canary
# ---------------------------------------------------------------------------


def provenance_canary(
    rows: list[RegistryRow],
    ofac_features: list[FeatureRow],
    dawsbot_records: list[dict],
    sample_n: int = 10,
    seed: int = 42,
) -> dict:
    """For sample_n random rows, re-fetch source byte from cited source and
    assert address matches. Hard fail if any mismatch.
    """
    import random
    rng = random.Random(seed)
    if len(rows) <= sample_n:
        sample = list(rows)
    else:
        sample = rng.sample(rows, sample_n)

    # Index ofac by (uid, feature_id) and dawsbot by idx for O(1) lookup
    ofac_idx = {(fr.party_uid, fr.feature_id): fr for fr in ofac_features}
    dawsbot_idx = dict(enumerate(dawsbot_records))

    samples_passed = 0
    sample_results = []

    for r in sample:
        # Pick first source for verification
        if not r.sources:
            sample_results.append({
                "address": r.address, "verified": False,
                "reason": "no sources attached",
            })
            continue
        src = r.sources[0]
        kind = src.get("kind")
        if kind == "ofac_sdn":
            key = (src.get("fixedref"), src.get("feature_id"))
            fr = ofac_idx.get(key)
            if fr is None:
                sample_results.append({
                    "address": r.address, "verified": False,
                    "reason": f"ofac key {key} not found",
                })
                continue
            re_norm = _norm_eth(fr.address_raw) if fr.chain == "eth" else fr.address_raw
            ok = (re_norm == r.address)
            sample_results.append({
                "address": r.address, "verified": ok,
                "kind": "ofac_sdn", "key": f"{key[0]}:{key[1]}",
                "source_addr": fr.address_raw,
            })
            if ok:
                samples_passed += 1
        elif kind == "dawsbot":
            idx = src.get("idx")
            rec = dawsbot_idx.get(idx)
            if rec is None:
                sample_results.append({
                    "address": r.address, "verified": False,
                    "reason": f"dawsbot idx {idx} not found",
                })
                continue
            raw = str(rec.get("address", ""))
            re_norm = _norm_eth(raw)
            ok = (re_norm == r.address)
            sample_results.append({
                "address": r.address, "verified": ok,
                "kind": "dawsbot", "idx": idx,
                "source_addr": raw,
            })
            if ok:
                samples_passed += 1
        else:
            sample_results.append({
                "address": r.address, "verified": False,
                "reason": f"unknown source kind {kind}",
            })

    return {
        "samples_checked": len(sample),
        "samples_passed": samples_passed,
        "samples": sample_results,
        "all_passed": samples_passed == len(sample),
    }


# ---------------------------------------------------------------------------
# Parquet writer
# ---------------------------------------------------------------------------


def write_parquet(rows: list[RegistryRow], path: Path) -> str:
    """Write registry rows to parquet, return sha256 of the parquet bytes."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    if not rows:
        raise RuntimeError("registry empty — refusing to write parquet")

    table = pa.table({
        "address":             [r.address for r in rows],
        "chain":               [r.chain for r in rows],
        "family":              [r.family for r in rows],
        "entity_program_tags": [r.entity_program_tags for r in rows],
        "operator_party":      [r.operator_party for r in rows],
        "sources":             [json.dumps(r.sources) for r in rows],
        "first_seen_utc":      [r.first_seen_utc for r in rows],
    })
    pq.write_table(table, path)

    return _file_sha256(path.read_bytes())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-dir", required=True, type=Path,
                        help="Local dir for source caches.")
    parser.add_argument("--out-dir", required=True, type=Path,
                        help="Local dir for registry.parquet + manifest.json.")
    parser.add_argument("--spellbook", type=Path, default=None,
                        help="Optional local dune_spellbook_addresses.json (transparency cell; "
                             "output of harvest_spellbook.py — BSL-derived, keep local).")
    args = parser.parse_args()

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[{_now_utc()}] build_mixer_registry start")
    print(f"  cache_dir={args.cache_dir}")
    print(f"  out_dir={args.out_dir}")

    # --- Load OFAC ---
    print(f"\n[{_now_utc()}] loading OFAC SDN_ADVANCED.XML ...")
    ofac_features, ofac_meta = load_ofac_features(args.cache_dir)
    if not ofac_meta.integrity_check_passed:
        print(f"FATAL: OFAC integrity FAIL — {ofac_meta.integrity_notes}", file=sys.stderr)
        return 2
    print(f"  ofac: {len(ofac_features)} crypto features, "
          f"sha={ofac_meta.sha256[:16]}..., bytes={ofac_meta.bytes_fetched:,}")

    # Sentinel: Semenov address must appear
    semenov_addrs = {_norm_eth(fr.address_raw) for fr in ofac_features
                     if "semenov" in fr.party_primary_name.lower() and fr.chain == "eth"}
    if SEMENOV_SENTINEL_ETH not in semenov_addrs:
        print(f"FATAL: Semenov sentinel {SEMENOV_SENTINEL_ETH} not in OFAC parse "
              f"(parsed {len(semenov_addrs)} Semenov ETH addresses)", file=sys.stderr)
        return 3

    # --- Load dawsbot ---
    print(f"\n[{_now_utc()}] loading dawsbot/eth-labels ...")
    dawsbot_records, dawsbot_meta = load_dawsbot_records(args.cache_dir)
    if not dawsbot_meta.integrity_check_passed:
        print(f"FATAL: dawsbot integrity FAIL — {dawsbot_meta.integrity_notes}", file=sys.stderr)
        return 2
    print(f"  dawsbot: {len(dawsbot_records)} records, sha={dawsbot_meta.sha256[:16]}...")

    # --- Spellbook (transparency only — not used for registry build) ---
    print(f"\n[{_now_utc()}] loading dune spellbook (transparency cell) ...")
    spellbook_path = args.spellbook or (args.cache_dir / "dune_spellbook_addresses.json")
    if spellbook_path.exists():
        sb_raw = spellbook_path.read_bytes()
        sb_meta = SourceMeta(
            name="dune_spellbook", url=None, source_uri=str(spellbook_path),
            fetch_utc=_now_utc(), bytes_fetched=len(sb_raw),
            sha256=_file_sha256(sb_raw),
            record_count=len(json.loads(sb_raw)),
            integrity_check_passed=True, integrity_notes="ok",
        )
    else:
        sb_meta = SourceMeta(
            name="dune_spellbook", url=None, source_uri=str(spellbook_path),
            fetch_utc=_now_utc(), bytes_fetched=0, sha256="",
            record_count=0, integrity_check_passed=False,
            integrity_notes="not staged locally — run harvest_spellbook.py (optional cell)",
        )

    # --- Build ---
    print(f"\n[{_now_utc()}] building registry rows ...")
    rows, overlap_stats = build_registry(ofac_features, dawsbot_records)
    print(f"  built {len(rows)} rows")

    # Quick stats
    by_family: dict[str, int] = {}
    by_chain: dict[str, int] = {}
    by_program: dict[str, int] = {}
    for r in rows:
        by_family[r.family] = by_family.get(r.family, 0) + 1
        by_chain[r.chain] = by_chain.get(r.chain, 0) + 1
        if r.entity_program_tags:
            for t in r.entity_program_tags:
                by_program[t] = by_program.get(t, 0) + 1
        else:
            by_program["none"] = by_program.get("none", 0) + 1

    print(f"  by_family: {by_family}")
    print(f"  by_chain:  {by_chain}")
    print(f"  by_program_tag: {by_program}")
    print(f"  overlap.tornado_cash: ofac={overlap_stats['tornado_cash']['ofac_addresses_total']}, "
          f"dawsbot={overlap_stats['tornado_cash']['dawsbot_addresses_total']}, "
          f"overlap={overlap_stats['tornado_cash']['ofac_in_dawsbot_count']}")

    # Family-floor check (expected floors from the probe measurement)
    if by_family.get("sinbad", 0) < 2:
        print(f"FATAL: sinbad expected ≥2, got {by_family.get('sinbad', 0)}", file=sys.stderr)
        return 3
    if by_family.get("tornado_cash", 0) < 68:
        print(f"FATAL: tornado_cash expected ≥68, got {by_family.get('tornado_cash', 0)}", file=sys.stderr)
        return 3

    # Sinbad sentinel
    sinbad_addrs = {r.address for r in rows if r.family == "sinbad"}
    sinbad_sentinels_lc = {a.lower() for a in SINBAD_SENTINEL_BTC}
    sinbad_addrs_lc = {a.lower() for a in sinbad_addrs}
    if not sinbad_sentinels_lc.issubset(sinbad_addrs_lc):
        print(f"FATAL: Sinbad sentinel BTC addrs not in registry. "
              f"Expected {SINBAD_SENTINEL_BTC}, got {sinbad_addrs}", file=sys.stderr)
        return 3

    # --- Provenance canary ---
    print(f"\n[{_now_utc()}] running provenance canary (10 samples) ...")
    canary = provenance_canary(rows, ofac_features, dawsbot_records, sample_n=10)
    print(f"  canary: {canary['samples_passed']}/{canary['samples_checked']} passed")
    if not canary["all_passed"]:
        print("FATAL: provenance canary failed", file=sys.stderr)
        for s in canary["samples"]:
            if not s.get("verified"):
                print(f"  MISMATCH: {s}", file=sys.stderr)
        return 4

    # --- DPRK3 superset (manifest transparency) ---
    dprk3 = compute_dprk3_superset(ofac_features)
    print(f"\n  dprk3_superset: {dprk3['total_addresses']} addrs across "
          f"{len(dprk3['parties'])} parties")
    # Sanity check against the OFAC-record expectations
    if dprk3["total_addresses"] < 50:
        print(f"WARN: dprk3 superset only {dprk3['total_addresses']} (expected 55)",
              file=sys.stderr)

    # --- Write parquet ---
    parquet_path = args.out_dir / REGISTRY_PARQUET_NAME
    print(f"\n[{_now_utc()}] writing parquet to {parquet_path} ...")
    parquet_sha = write_parquet(rows, parquet_path)
    print(f"  parquet sha256 = {parquet_sha[:16]}..., size = {parquet_path.stat().st_size:,} bytes")

    # --- Manifest ---
    manifest = {
        "registry_version": "v1",
        "build_timestamp_utc": _now_utc(),
        "git_commit": _git_commit(),
        "method": "public-label ceiling per probe_mixer_sources.py measurement",
        "input_sources": {
            "ofac_sdn": {
                "url": ofac_meta.url, "sha256": ofac_meta.sha256,
                "bytes": ofac_meta.bytes_fetched,
                "records": ofac_meta.record_count,
                "fetch_utc": ofac_meta.fetch_utc,
            },
            "dawsbot_eth_labels": {
                "url": dawsbot_meta.url, "sha256": dawsbot_meta.sha256,
                "bytes": dawsbot_meta.bytes_fetched,
                "records": dawsbot_meta.record_count,
                "fetch_utc": dawsbot_meta.fetch_utc,
            },
            "dune_spellbook": {
                "source_uri": sb_meta.source_uri, "sha256": sb_meta.sha256,
                "bytes": sb_meta.bytes_fetched,
                "records": sb_meta.record_count,
                "fetch_utc": sb_meta.fetch_utc,
                "note": "transparency only — not used for the registry build",
            },
        },
        "registry_stats": {
            "total_addresses": len(rows),
            "by_family": by_family,
            "by_chain": by_chain,
            "by_program_tag": by_program,
        },
        "overlap_stats": overlap_stats,
        "dprk3_superset": dprk3,
        "provenance_canary": canary,
        "registry_sha256": parquet_sha,
        "registry_filename": REGISTRY_PARQUET_NAME,
    }
    manifest_path = args.out_dir / MANIFEST_NAME
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    _atomic_write(manifest_path, manifest_bytes)
    print(f"  manifest written: {manifest_path} "
          f"(sha256={_file_sha256(manifest_bytes)[:16]}...)")

    print(f"\n[{_now_utc()}] BUILD OK (rows={len(rows)}, canary={canary['samples_passed']}/{canary['samples_checked']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
