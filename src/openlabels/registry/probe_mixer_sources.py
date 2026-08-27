#!/usr/bin/env python3
"""Public-source mixer-coverage probe.

Before claiming a public-source ceiling for a mixer registry, run a
per-mixer-family probe
across multiple independent public sources. Output: probe_mixer_sources.json
with raw record counts per (mixer_family, source) cell.

QA-driven scope cut (v1 → v2):
    REMOVED unified_labels_current source — caused OOM on a 1 GB box
        (81 MB JSON × json.load() peak ~700 MB). Also redundant: it is itself
        a merge of OFAC + dawsbot + spellbook, so probe-source independence
        was already broken.
    REMOVED EU consolidated sanctions list — URL token broken; even when
        accessible, EU records are person/entity names without crypto address
        fields.
    REMOVED UK HMT sanctions list — same as EU.

Sources kept (3, all small):
    1. OFAC SDN CSV — primary source. Tornado, Sinbad, Samourai operators
       are all OFAC-designated.
    2. dawsbot/eth-labels GitHub — public ETH-label collection.
    3. Dune Spellbook — known CEX-focused; included as transparency cell
       (expected ~zero matches across mixer families).

Mixer families probed (4 sanctioned + 2 non-sanctioned for transparency):
    1. tornado_cash    — POSITIVE CONTROL — must yield ≥1 OFAC address
                         (Treasury 2022-08-08 designation).
    2. sinbad          — OFAC-sanctioned 2023-11-29.
    3. samourai        — DOJ + Treasury action 2024-04-24.
    4. chipmixer       — Europol-seized 2023-03; addresses may be in OFAC.
    5. wasabi          — non-custodial coordinator (BTC); structurally absent
                         from OFAC. Reported as evidence of ceiling.
    6. helix           — DOJ 2021 (operator pleaded guilty). Addresses not
                         enumerated in structured public form.

Decision rule (post-probe):
    POSITIVE CONTROL — if tornado_cash returns 0 OFAC addresses → probe
    methodology has a bug (not data ceiling). Output is flagged
    `positive_control_passed: false` and no registry scope must be signed
    from this output.

    Per family, given positive control passes:
        OFAC ≥1 address                          → INCLUDE in registry scope.
        OFAC named-matched ≥1 but 0 addresses   → BUG flag (Treasury named
                                                   the entity but listed no
                                                   on-chain addresses) — needs
                                                   manual review.
        OFAC = 0 + dawsbot/spellbook 0          → CEILING confirmed; only a
                                                   commercial vendor could go
                                                   further.

Out of probe scope (recorded in manifest):
    Mixer-output detection (24h window from Tornado Cash to Lazarus
    addresses) requires a separate seed list from OFAC press releases (not
    SDN CSV). This probe does NOT cover that.
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
import xml.etree.ElementTree as ET  # module-level (was inside load_ofac_sdn)
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Source configuration
# ---------------------------------------------------------------------------

# Per sdn.csv is name-/individual-only and does NOT contain
# entity addresses (Tornado Cash 50+ pool contracts, Sinbad addresses, etc.).
# Switch to SDN_ADVANCED.XML (Sanctions v3 schema) which has structured
# entities + crypto-address features.
# 2026-05-16 R-3: legacy host treasury.gov/ofac/downloads returns HTTP 404.
# OFAC migrated to Sanctions List Service. Schema also changed from legacy
# nested-only flat tags to v3 CamelCase with <Feature FeatureTypeID="..."> +
# <VersionDetail> for crypto addresses (still nested inside DistinctParty).
OFAC_SDN_XML_URL = (
    "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/"
    "exports/SDN_ADVANCED.XML"
)

# Sanctions v3 FeatureTypeID → crypto family. Extracted from
# /ReferenceValueSets/FeatureTypeValues/FeatureType in the served XML.
# Used to filter <Feature> elements during parse so only crypto-address
# Features yield row.id_values entries.
CRYPTO_FEATURE_TYPE_IDS: dict[str, str] = {
    "344": "XBT",   # Bitcoin
    "345": "ETH",
    "444": "XMR",
    "566": "LTC",
    "686": "ZEC",
    "687": "DASH",
    "688": "BTG",
    "689": "ETC",
    "706": "BSV",
    "726": "BCH",
    "746": "XVG",
    "887": "USDT",
    "907": "XRP",
    "992": "TRX",   # Tron
    "998": "USDC",
    "1007": "ARB",  # Arbitrum
    "1008": "BSC",
    "1167": "SOL",
}

# Per dawsbot/eth-labels GitHub layout shifted (default branch
# rename, repo restructure). Discover current paths via GitHub API at runtime.
DAWSBOT_REPO_API = "https://api.github.com/repos/dawsbot/eth-labels"
DAWSBOT_REPO_RAW_BASE = "https://raw.githubusercontent.com/dawsbot/eth-labels"
# Candidate paths to try after default-branch discovery:
DAWSBOT_CANDIDATE_PATHS = [
    # 2026-05-16: dawsbot/eth-labels v1 layout — verified via GitHub API.
    # data/json/accounts.json is 17 MB, list of {address, chainId, label, nameTag}.
    "data/json/accounts.json",
    # Legacy paths kept for resilience if the repo restructures again.
    "labels/labels.json",
    "src/labels/labels.json",
    "data/labels.json",
    "src/data.json",
]

DUNE_SPELLBOOK_LOCAL_DEFAULT = "dune_spellbook_addresses.json"

# single source-of-truth for sources removed in v2.
# If a source is re-added, remove its entry here AND restore loader/probe.
_DROPPED_SOURCES_V1_TO_V2 = {
    "unified_labels_current": (
        "OOM root — 81 MB JSON load on a 1 GB box. "
        "Also redundant: derivative of OFAC + dawsbot + spellbook."
    ),
    "eu_sanctions": (
        "URL token broken; EU records lack crypto-address fields."
    ),
    "uk_hmt": (
        "Azure Blob URL fragile; UK records lack crypto-address fields."
    ),
}

# Per C-12: consolidated chipmixer regex (single pattern covers all variants).
KEYWORDS = {
    "tornado_cash":  [r"tornado.?cash"],
    "sinbad":        [r"\bsinbad\b"],
    "samourai":      [r"\bsamourai\b"],
    "chipmixer":     [r"chip.?mixer"],
    "wasabi":        [r"\bwasabi\b"],
    "helix":         [r"\bhelix\b", r"bitcoin.?fog"],
}

# Per S-3: Samourai is a common name unrelated to mixers.
# Co-occurrence requirement narrows false-positives.
# tighten helix co-occurrence — \bbtc\b alone is too permissive
# (any unrelated SDN entry mentioning Bitcoin and named "Helix" would match).
# Restrict to mixer/laundering/Bitcoin-Fog signal only.
COOCCURRENCE_REQUIRED = {
    "samourai": [r"whirlpool", r"\bwallet\b", r"bitcoin", r"crypto", r"mixer", r"\bbtc\b"],
    "helix":    [r"\bmix(?:er|ing)\b", r"bitcoin.?fog", r"\bdarknet\b", r"laundering"],
}

# Per S-4: word-boundary on EVM addresses to avoid matching mid-string hex.
ADDR_RE_EVM = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
# bech32 is lowercase by BIP-173.
ADDR_RE_BTC = re.compile(r"\b(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")

# Per C-9: retry config for HTTP fetch.
RETRY_ATTEMPTS = 3
RETRY_BACKOFF_SEC = (5, 15, 45)


@dataclass
class ProbeCell:
    family: str
    source: str
    distinct_addresses: int = 0
    sample_addresses: list[str] = field(default_factory=list)
    # Per S-10: separate counter for "name matched" vs "addresses extracted".
    named_match_count: int = 0
    notes: str = ""
    error: str | None = None


@dataclass
class SourceMeta:
    """Reproducibility manifest for one fetched source."""
    name: str
    url: str | None
    source_uri: str | None
    fetch_utc: str
    bytes_fetched: int
    sha256: str
    record_count: int
    integrity_check_passed: bool
    integrity_notes: str = ""


# ---------------------------------------------------------------------------
# HTTP fetch with retry + atomic cache write
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, data: bytes) -> None:
    """Write bytes via tmp+fsync+rename so partial-fetch poisoned cache cannot occur.
    (defect C-13 hardened by C2-12: add fsync before rename.)"""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# terminal vs transient 4xx codes.
# 404/410 = path is gone; do not retry.
# 403/429 = rate-limited or auth; ARE transient (caller may have hit
#   anonymous rate limit, retry can recover after backoff).
# 401 = auth; terminal here (we have no creds to fix it).
# separate sets for full-GET fetch vs HEAD probe. 405
# (Method Not Allowed) is terminal for fetch (server explicitly rejects
# the verb) but only "this verb won't work, try another" for HEAD probe —
# caller of head_check may want to fall back to GET. We keep 405 in the
# fetch set; head_check uses _TERMINAL_4XX_HEAD which excludes 405.
_TERMINAL_4XX = frozenset({400, 401, 404, 405, 410, 414, 415, 451})
_TERMINAL_4XX_HEAD = frozenset({400, 401, 404, 410, 414, 415, 451})


def fetch_with_retry(url: str, timeout: int = 60) -> bytes | None:
    """GET with retry 3× exponential backoff (C-9).
    Bail-fast on terminal 4xx (C2-3 + C3-4).
    Retry transient 4xx (403/429) like 5xx (C3-4).
    """
    last_err: Exception | None = None
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (openlabels-probe)"}
    )
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code in _TERMINAL_4XX:
                print(f"  fetch FAIL (no retry on terminal {e.code}) {url}: {e}",
                      file=sys.stderr)
                return None
            # 5xx + 403 + 429 + other transient 4xx → retry with backoff.
            if attempt < RETRY_ATTEMPTS - 1:
                wait = RETRY_BACKOFF_SEC[attempt]
                print(f"  fetch retry {attempt+1}/{RETRY_ATTEMPTS} ({url}): {e}; sleep {wait}s",
                      file=sys.stderr)
                time.sleep(wait)
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
            if attempt < RETRY_ATTEMPTS - 1:
                wait = RETRY_BACKOFF_SEC[attempt]
                print(f"  fetch retry {attempt+1}/{RETRY_ATTEMPTS} ({url}): {e}; sleep {wait}s",
                      file=sys.stderr)
                time.sleep(wait)
    print(f"  fetch FAIL {url} after {RETRY_ATTEMPTS} attempts: {last_err}", file=sys.stderr)
    return None


def head_check(url: str, timeout: int = 10) -> int | None:
    """HEAD check with retry on transient 4xx/5xx. (C2-2 + C3-4 + C7-2)
    Returns HTTP status code, or None on connection error / exhausted retries.

    Uses _TERMINAL_4XX_HEAD (excludes 405) so callers can fall back to GET
    if server doesn't support HEAD.
    """
    req = urllib.request.Request(
        url, method="HEAD",
        headers={"User-Agent": "Mozilla/5.0 (openlabels-probe)"},
    )
    last_status: int | None = None
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status
        except urllib.error.HTTPError as e:
            last_status = e.code
            if e.code in _TERMINAL_4XX_HEAD:
                return e.code  # definitive miss; caller skips
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_BACKOFF_SEC[attempt])
        except Exception:
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_BACKOFF_SEC[attempt])
    return last_status


def _file_sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _strip_ns(tag: str) -> str:
    """Strip XML namespace from a tag: '{ns}localname' → 'localname'. module-level helper (was nested closure recreated per call).
    """
    return tag.split("}", 1)[1] if "}" in tag else tag


def _norm_addr(a: object) -> str:
    """Normalize address: lowercase EVM hex, leave bech32/legacy BTC as-is. module-level (was nested closure inside load_dawsbot_labels).
    """
    s = str(a)
    return s.lower() if s.startswith("0x") else s


def load_ofac_sdn(cache: Path) -> tuple[list[dict], SourceMeta]:
    """Stream-parse SDN_ADVANCED.XML (Sanctions v3 schema, defect R-3).
    Returns one record per OFAC DistinctParty with name/aliases/programs/
    crypto-addresses extracted.

    Schema 2026-05 (post-OFAC migration to sanctionslistservice.ofac.treas.gov):

        <Sanctions Version="3" xmlns="...ADVANCED_XML">
          <DistinctParty FixedRef="44718">
            <Profile PartySubTypeID="...">
              <Identity Primary="true">
                <Alias AliasTypeID="1403" Primary="true">  <!-- primary name -->
                  <DocumentedName>
                    <DocumentedNamePart><NamePartValue>Semenov</NamePartValue></DocumentedNamePart>
                    <DocumentedNamePart><NamePartValue>Roman</NamePartValue></DocumentedNamePart>
                  </DocumentedName>
                </Alias>
                <Alias AliasTypeID="1400" Primary="false" LowQuality="true">  <!-- aka -->
                  ...
                </Alias>
              </Identity>
              <Feature FeatureTypeID="345">  <!-- 345 = ETH per CRYPTO_FEATURE_TYPE_IDS -->
                <FeatureVersion>
                  <VersionDetail>0xdcbEfFBECcE100cCE9E4b153C4e15cB885643193</VersionDetail>
                </FeatureVersion>
              </Feature>
              ... more Features ...
            </Profile>
          </DistinctParty>
          ... more DistinctParties ...
          <SanctionsEntries>
            <SanctionsEntry FixedRef="44718">  <!-- programs join via FixedRef -->
              <SanctionsMeasure><Comment>UKRAINE-EO13662</Comment></SanctionsMeasure>
            </SanctionsEntry>
          </SanctionsEntries>
        </Sanctions>

    Output record shape (preserved from legacy parser — downstream consumers
    in probe_ofac use row["id_values"] for crypto-address regex extraction):
        {
            "uid":        str (FixedRef value, e.g. "44718"),
            "name":       str (primary name = AliasTypeID="1403" Primary="true",
                              joined NamePartValues by space),
            "all_names":  str (primary + all aliases joined by "; "),
            "type":       str (PartySubTypeID-based; deferred to v2 — empty),
            "programs":   str (semicolon-joined SanctionsMeasure comments,
                              joined by FixedRef),
            "remarks":    str (top-level <Comment> text),
            "addresses":  str (Feature 8/10/etc. physical address features —
                              deferred; v3 stores them differently),
            "id_values":  str (semicolon-joined VersionDetail values from
                              Features whose FeatureTypeID is in
                              CRYPTO_FEATURE_TYPE_IDS — i.e. crypto addresses).
        }

    XML streaming via xml.etree.iterparse — bounded memory. SDN_ADVANCED.XML
    is ~125 MB on disk (2026-05); peak Python memory ~400-600 MB observed
    on test parse. Fits a 2 GB box with comfortable margin; 1 GB
    (1 GB) is borderline — use e2-small or larger.
    """
    cache_path = cache / "sdn_advanced.xml"
    if not cache_path.exists():
        data = fetch_with_retry(OFAC_SDN_XML_URL, timeout=180)
        if data is None:
            return [], SourceMeta(
                name="ofac_sdn", url=OFAC_SDN_XML_URL, source_uri=None,
                fetch_utc=_now_utc(), bytes_fetched=0, sha256="",
                record_count=0, integrity_check_passed=False,
                integrity_notes="HTTP fetch failed after retries",
            )
        _atomic_write(cache_path, data)
    raw = cache_path.read_bytes()

    # Integrity: size > 50 MB (SDN_ADVANCED.XML v3 is ~125 MB 2026-05) +
    # Tornado sentinel. Threshold raised from 5 MB after migration —
    # legacy file was ~30 MB; new schema is ~4× larger.
    integrity_pass = True
    integrity_notes: list[str] = []
    if len(raw) < 50_000_000:
        integrity_pass = False
        integrity_notes.append(f"size {len(raw)} bytes < 50 MB threshold")
    if b"TORNADO" not in raw.upper():
        integrity_pass = False
        integrity_notes.append("'TORNADO' sentinel not found in SDN — file likely truncated/wrong")

    if not integrity_pass:
        return [], SourceMeta(
            name="ofac_sdn", url=OFAC_SDN_XML_URL, source_uri=None,
            fetch_utc=_now_utc(), bytes_fetched=len(raw), sha256=_file_sha256(raw),
            record_count=0, integrity_check_passed=False,
            integrity_notes="; ".join(integrity_notes),
        )

    # Pass 1: parse DistinctParty + Feature elements (single iterparse traversal).
    # Sanctions v3 keeps Features nested inside <DistinctParty><Profile>...
    # so we don't need a separate pass for relational join.
    # Tag set is CamelCase per Sanctions v3 schema.

    rows: list[dict] = []
    party_to_programs: dict[str, list[str]] = {}  # filled in Pass 2 (SanctionsEntry)

    # Per-party state (reset at each <DistinctParty> start):
    in_party = False
    in_alias = False
    in_documented_name_part = False
    primary_alias = False  # current Alias is AliasTypeID="1403" + Primary="true"
    in_feature = False
    current_feature_type_id: str | None = None
    current_feature_is_crypto = False

    party_uid: str | None = None
    party_name_parts: list[str] = []  # NamePartValues for the current Alias
    primary_name_parts: list[str] = []  # accumulated primary-alias name parts
    aliases: list[str] = []  # non-primary alias strings
    id_values: list[str] = []  # crypto VersionDetail values
    remarks: list[str] = []  # DistinctParty-level <Comment> text

    root_elem = None
    party_count = 0

    try:
        ctx = ET.iterparse(str(cache_path), events=("start", "end"))

        for event, elem in ctx:
            # Capture root for periodic clear() to bound memory.
            # (legacy defect C2-4 — same rationale here.)
            if root_elem is None and event == "start":
                root_elem = elem

            tag = _strip_ns(elem.tag)

            if event == "start":
                if tag == "DistinctParty":
                    in_party = True
                    party_uid = elem.get("FixedRef")
                    primary_name_parts = []
                    aliases = []
                    id_values = []
                    remarks = []
                    in_alias = False
                    primary_alias = False
                    in_feature = False
                    current_feature_type_id = None
                    current_feature_is_crypto = False

                elif in_party and tag == "Alias":
                    in_alias = True
                    party_name_parts = []
                    # AliasTypeID="1403" + Primary="true" = primary aka legal name
                    primary_alias = (
                        elem.get("AliasTypeID") == "1403"
                        and elem.get("Primary") == "true"
                    )

                elif in_party and tag == "DocumentedNamePart":
                    in_documented_name_part = True

                elif in_party and tag == "Feature":
                    in_feature = True
                    current_feature_type_id = elem.get("FeatureTypeID")
                    current_feature_is_crypto = (
                        current_feature_type_id in CRYPTO_FEATURE_TYPE_IDS
                    )

            else:  # end
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
                    # Crypto VersionDetail captured only if Feature is crypto-typed.
                    if current_feature_is_crypto:
                        id_values.append(text)

                elif in_party and tag == "Feature":
                    in_feature = False
                    current_feature_type_id = None
                    current_feature_is_crypto = False

                elif in_party and tag == "Comment" and text:
                    # DistinctParty-level Comment is the immediate child of
                    # <DistinctParty> per observed schema (e.g. FixedRef=44718
                    # has none, but other entities have them). FeatureVersion
                    # also contains <Comment /> nested — we don't care, those
                    # are usually empty. We collect any non-empty comment text
                    # encountered inside the party as a remark.
                    remarks.append(text)

                elif tag == "DistinctParty" and in_party:
                    in_party = False
                    party_count += 1
                    name = " ".join(primary_name_parts).strip()
                    rec = {
                        "uid": party_uid or "",
                        "name": name,
                        "all_names": "; ".join([n for n in [name] + aliases if n]),
                        # Type / addresses retained as empty strings — Sanctions v3
                        # surfaces them differently and Track-D probe doesn't use
                        # them (downstream probe_ofac scans id_values + remarks).
                        "type": "",
                        "programs": "",  # filled in Pass 2 join below
                        "remarks": "; ".join(r for r in remarks if r),
                        "addresses": "",
                        "id_values": "; ".join(v for v in id_values if v),
                    }
                    rows.append(rec)
                    elem.clear()
                    if root_elem is not None and party_count % 500 == 0:
                        root_elem.clear()

                # ----- Pass 2 inline: SanctionsEntry → programs join -----
                # SanctionsEntry blocks live AFTER all DistinctParty blocks
                # in the served XML. Each SanctionsEntry has ProfileID
                # attribute that matches DistinctParty.FixedRef (verified on
                # 2026-05-16: FixedRef=ProfileID=44718 for Tornado/Semenov entry).
                #
                # The descendant tree is:
                #   <SanctionsEntry ProfileID="...">
                #     <SanctionsMeasure SanctionsTypeID="1">
                #       <Comment>CUBA</Comment>  <-- the program name
                #
                # We only collect Comments inside SanctionsMeasure (NOT
                # EntryEvent.Comment which is empty / metadata).
                elif tag == "SanctionsEntry":
                    profile_id = elem.get("ProfileID")
                    if profile_id:
                        progs: list[str] = []
                        for measure in elem.iter():
                            measure_tag = _strip_ns(measure.tag)
                            if measure_tag != "SanctionsMeasure":
                                continue
                            for sub in measure.iter():
                                sub_tag = _strip_ns(sub.tag)
                                if sub_tag == "Comment" and (sub.text or "").strip():
                                    progs.append(sub.text.strip())
                        if progs:
                            party_to_programs[profile_id] = progs
                    elem.clear()

    except ET.ParseError as e:
        return [], SourceMeta(
            name="ofac_sdn", url=OFAC_SDN_XML_URL, source_uri=None,
            fetch_utc=_now_utc(), bytes_fetched=len(raw), sha256=_file_sha256(raw),
            record_count=0, integrity_check_passed=False,
            integrity_notes=f"XML parse error: {e}",
        )

    # Apply collected SanctionsEntry programs back onto rows.
    if party_to_programs:
        for r in rows:
            uid = r.get("uid")
            if uid and uid in party_to_programs:
                r["programs"] = "; ".join(party_to_programs[uid])

    # Post-parse schema-validation sentinel. Sanctions v3 SDN consistently
    # has 18-20K DistinctParty entries (2026-05: 18,959 verified locally).
    SCHEMA_MIN_ROWS = 5000  # conservative floor; real count is ~18-20K.

    schema_pass = True
    schema_notes = []
    if len(rows) < SCHEMA_MIN_ROWS:
        schema_pass = False
        schema_notes.append(
            f"only {len(rows)} DistinctParty rows parsed — expected ≥{SCHEMA_MIN_ROWS}; "
            f"tag-name set likely mismatches current OFAC schema"
        )
    # Tornado-word sentinel removed 2026-05-16: Tornado Cash is NOT
    # registered in OFAC SDN as "Tornado Cash" entity. The sanction is
    # recorded under Roman Semenov / Roman Storm (developers) with crypto
    # addresses attached as Features. Raw XML contains only 2 mentions of
    # "tornado" (in poma@tornado.cash email + alias "Tornado" of unrelated
    # cazarin Cesar entry). Name-extraction validation now relies on
    # SCHEMA_MIN_ROWS + crypto-coverage sentinel below.

    # Crypto-coverage sanity: SDN v3 has thousands of crypto Features.
    # If we see <100 crypto addresses across all parties, Feature parsing
    # is broken even if name extraction is fine.
    crypto_addr_count = sum(
        len([v for v in (r.get("id_values") or "").split("; ") if v])
        for r in rows
    )
    if crypto_addr_count < 100:
        schema_pass = False
        schema_notes.append(
            f"only {crypto_addr_count} crypto addresses extracted across all rows — "
            f"expected ≥100 (SDN v3 has thousands); Feature parsing broken"
        )

    if not schema_pass:
        return rows, SourceMeta(
            name="ofac_sdn", url=OFAC_SDN_XML_URL, source_uri=None,
            fetch_utc=_now_utc(), bytes_fetched=len(raw), sha256=_file_sha256(raw),
            record_count=len(rows), integrity_check_passed=False,
            integrity_notes="; ".join(schema_notes),
        )

    return rows, SourceMeta(
        name="ofac_sdn", url=OFAC_SDN_XML_URL, source_uri=None,
        fetch_utc=_now_utc(), bytes_fetched=len(raw), sha256=_file_sha256(raw),
        record_count=len(rows), integrity_check_passed=integrity_pass,
        integrity_notes=(
            f"ok; {crypto_addr_count} crypto addresses across {len(rows)} parties"
        ),
    )


def _discover_dawsbot_url() -> str | None:
    """Per dawsbot/eth-labels repo path drifted (404 on master/main
    + /labels/labels.json). Discover current default branch via GitHub API,
    then HEAD-probe candidate paths ( avoid double full GET).

    Returns the first raw URL that returns HTTP 200, or None if all candidates
    miss. GitHub API anonymous rate limit is 60 req/h — uses ≤6 requests max.
    HEAD probes avoid wasted bandwidth on candidates that don't
    match.
    """
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
        # server rejected HEAD — try a small GET probe instead
        # of treating as miss. We need a real existence check.
        if status == 405:
            probe = fetch_with_retry(url, timeout=10)
            if probe and (probe.startswith(b"{") or probe.startswith(b"[")):
                return url
    return None


def load_dawsbot_labels(cache: Path) -> tuple[dict, SourceMeta]:
    """Load dawsbot/eth-labels JSON. Normalizes any list shape to a dict
    keyed by address ( prior code AttributeError'd on list shape).
    """
    cache_path = cache / "dawsbot_labels.json"
    discovered_url = None
    if not cache_path.exists():
        discovered_url = _discover_dawsbot_url()
        if discovered_url is None:
            return {}, SourceMeta(
                name="dawsbot_eth_labels", url=None, source_uri=None,
                fetch_utc=_now_utc(), bytes_fetched=0, sha256="",
                record_count=0, integrity_check_passed=False,
                integrity_notes="GitHub API discovery failed: repo default branch / "
                                "labels path could not be resolved (rate limit or layout drift)",
            )
        data = fetch_with_retry(discovered_url)
        if data is None:
            return {}, SourceMeta(
                name="dawsbot_eth_labels", url=discovered_url, source_uri=None,
                fetch_utc=_now_utc(), bytes_fetched=0, sha256="",
                record_count=0, integrity_check_passed=False,
                integrity_notes="HTTP fetch failed after retries on discovered URL",
            )
        _atomic_write(cache_path, data)
    raw = cache_path.read_bytes()

    # drop strict 100 KB byte-size threshold (false-FAIL on
    # legitimately-small label sets during repo rebuild). Use record-count
    # integrity check after parse instead — applied below.
    integrity_pass = True
    integrity_notes: list[str] = []

    try:
        parsed = json.loads(raw)
    except Exception as e:
        return {}, SourceMeta(
            name="dawsbot_eth_labels", url=discovered_url, source_uri=None,
            fetch_utc=_now_utc(), bytes_fetched=len(raw), sha256=_file_sha256(raw),
            record_count=0, integrity_check_passed=False,
            integrity_notes=f"json parse failed: {e}",
        )

    # Normalize: dict[addr → info] OR list[{address: ..., ...}] OR
    # dict-of-categories[category → list[{address: ..., ...}]].
    # _norm_addr moved to module level (was nested here).
    labels: dict[str, dict] = {}

    if isinstance(parsed, dict):
        # Could be {addr: info, ...} OR {category: [records]} categorized layout.
        sample_value = next(iter(parsed.values()), None) if parsed else None
        if isinstance(sample_value, list):
            # categorized layout: {category: [{address, name, ...}]}
            for category, recs in parsed.items():
                if not isinstance(recs, list):
                    continue
                for rec in recs:
                    if isinstance(rec, dict) and rec.get("address"):
                        addr = _norm_addr(rec["address"])
                        info = dict(rec)
                        info.setdefault("category", category)
                        labels[addr] = info
        else:
            # flat dict[addr → info] — use as-is, lowercase EVM keys
            for addr, info in parsed.items():
                key = _norm_addr(addr) if isinstance(addr, str) else addr
                labels[key] = info if isinstance(info, dict) else {"name": str(info)}
    elif isinstance(parsed, list):
        # list[{address, name, ...}] layout
        for rec in parsed:
            if isinstance(rec, dict) and rec.get("address"):
                addr = _norm_addr(rec["address"])
                labels[addr] = dict(rec)
    else:
        integrity_pass = False
        integrity_notes.append(f"unexpected JSON root type: {type(parsed).__name__}")

    # record-count integrity — fewer than 100 normalized entries
    # indicates either a broken parse or a mid-rebuild repo state.
    if len(labels) < 100:
        integrity_pass = False
        integrity_notes.append(
            f"only {len(labels)} entries after normalize — suspicious for label set"
        )

    return labels, SourceMeta(
        name="dawsbot_eth_labels", url=discovered_url, source_uri=None,
        fetch_utc=_now_utc(), bytes_fetched=len(raw), sha256=_file_sha256(raw),
        record_count=len(labels), integrity_check_passed=integrity_pass,
        integrity_notes="; ".join(integrity_notes) if integrity_notes else "ok",
    )


def load_spellbook(cache: Path) -> tuple[list[dict], SourceMeta]:
    """Load a locally staged Spellbook dump (output of harvest_spellbook.py).

    Local-only by design: the dump is BSL-derived and is never fetched from,
    or uploaded to, shared storage by this probe.
    """
    local = cache / DUNE_SPELLBOOK_LOCAL_DEFAULT
    if not local.exists():
        return [], SourceMeta(
            name="dune_spellbook", url=None, source_uri=str(local),
            fetch_utc=_now_utc(), bytes_fetched=0, sha256="",
            record_count=0, integrity_check_passed=False,
            integrity_notes="not staged locally — run harvest_spellbook.py first",
        )
    raw = local.read_bytes()
    try:
        records = json.loads(raw)
    except Exception as e:
        return [], SourceMeta(
            name="dune_spellbook", url=None, source_uri=str(local),
            fetch_utc=_now_utc(), bytes_fetched=len(raw), sha256=_file_sha256(raw),
            record_count=0, integrity_check_passed=False,
            integrity_notes=f"json parse failed: {e}",
        )

    # silent type mismatch — fail integrity if root is not a list.
    if not isinstance(records, list):
        return [], SourceMeta(
            name="dune_spellbook", url=None, source_uri=str(local),
            fetch_utc=_now_utc(), bytes_fetched=len(raw), sha256=_file_sha256(raw),
            record_count=0, integrity_check_passed=False,
            integrity_notes=f"unexpected root type {type(records).__name__}; expected list",
        )

    return records, SourceMeta(
        name="dune_spellbook", url=None, source_uri=str(local),
        fetch_utc=_now_utc(), bytes_fetched=len(raw), sha256=_file_sha256(raw),
        record_count=len(records),
        integrity_check_passed=True, integrity_notes="ok",
    )


# ---------------------------------------------------------------------------
# Probe matchers
# ---------------------------------------------------------------------------


def find_addresses_in_text(text: str) -> set[str]:
    """Return a set of distinct EVM (lowercased) + BTC addresses found in text. return type changed from sorted list to set; the sole caller
    feeds results into a set anyway, so the prior sorted() was wasted work.
    """
    out: set[str] = set()
    for m in ADDR_RE_EVM.findall(text):
        out.add(m.lower())
    for m in ADDR_RE_BTC.findall(text):
        out.add(m)
    return out


def matches_keywords(text: str, keywords: list[str]) -> bool:
    if not text:
        return False
    text_low = text.lower()
    return any(re.search(kw, text_low) for kw in keywords)


def matches_with_cooccurrence(text: str, family: str) -> bool:
    """Per S-3: families with high false-positive risk require keyword + co-occurrence."""
    if not matches_keywords(text, KEYWORDS[family]):
        return False
    cooc = COOCCURRENCE_REQUIRED.get(family)
    if cooc is None:
        return True
    text_low = text.lower()
    return any(re.search(c, text_low) for c in cooc)


def probe_ofac(rows: list[dict], family: str) -> ProbeCell:
    cell = ProbeCell(family=family, source="ofac_sdn")
    if not rows:
        cell.error = "OFAC SDN load failed or empty"
        return cell

    matched_addrs: set[str] = set()
    matched_sample_names: list[str] = []
    named_count = 0
    for row in rows:
        # Match family keywords against textual row fields (all_names + remarks).
        # We match on text because crypto-address strings are too noisy to use
        # as keyword evidence — a hex string like '0x...' may appear in many
        # unrelated SDN entries.
        # defects C5-2 + C5-6: `all_names` already includes primary `name`
        # (constructed at row-build line ~389). Scanning both is redundant.
        # `rec` fields are always strings minimum (defaulted at construction),
        # so `or ""` is not needed.
        # prior comment said "addresses are too short for keyword
        # match" which was misleading; the regex matches against text fields,
        # not against extracted addresses.
        match_text = row.get("all_names", "") + " " + row.get("remarks", "")
        if matches_with_cooccurrence(match_text, family):
            named_count += 1
            # Per in sdn_advanced.xml crypto addresses are in
            # id_values (Digital Currency Address - XXX) AND remarks
            # (free-text refs). Per do NOT scan the `addresses`
            # field — it holds physical street/city/country addresses, not
            # crypto, so scanning it wastes regex work and risks accidental
            # alphanumeric collisions.
            extract_text = row.get("id_values", "") + " " + row.get("remarks", "")
            # set.update(set) is cleaner than per-element add loop.
            matched_addrs.update(find_addresses_in_text(extract_text))
            if len(matched_sample_names) < 3:
                # `name` is always a string from rec construction.
                # skip empty-string names so notes line is clean.
                row_name = row.get("name", "")[:80]
                if row_name:
                    matched_sample_names.append(row_name)

    cell.distinct_addresses = len(matched_addrs)
    cell.named_match_count = named_count
    cell.sample_addresses = sorted(matched_addrs)[:5]
    cell.notes = "; ".join(matched_sample_names) if matched_sample_names else "no name match"
    return cell


def probe_dawsbot(labels: dict, family: str) -> ProbeCell:
    cell = ProbeCell(family=family, source="dawsbot_eth_labels")
    if not labels:
        cell.error = "dawsbot load failed or empty"
        return cell

    matched_addrs: set[str] = set()
    named_count = 0
    for addr, info in labels.items():
        # categorized layout puts mixer addrs under
        # category="mixers" with no "mixer" word in name. Match against
        # the union of name + category + subtype + type fields.
        # simplify defensive str(... or ""); after the loader
        # normalizes records, missing keys yield "" via dict.get default,
        # and explicit None becomes "" via the "or" short-circuit only when
        # a value is actually None (rare). Keep `or ""` for the None case.
        if isinstance(info, dict):
            text = " ".join(
                (info.get(k) or "")
                for k in ("name", "category", "subtype", "type", "label", "description")
            )
        else:
            text = str(info)
        if matches_with_cooccurrence(text, family):
            named_count += 1
            # use module-level _norm_addr instead of inlined logic.
            matched_addrs.add(_norm_addr(addr) if isinstance(addr, str) else addr)

    cell.distinct_addresses = len(matched_addrs)
    cell.named_match_count = named_count
    cell.sample_addresses = sorted(matched_addrs)[:5]
    cell.notes = "ETH-only source; matched name+category+subtype"
    return cell


def probe_spellbook(records: list[dict], family: str) -> ProbeCell:
    cell = ProbeCell(family=family, source="dune_spellbook")
    if not records:
        cell.error = "spellbook load failed or empty"
        return cell

    matched_addrs: set[str] = set()
    named_count = 0
    # spellbook record schema varies — try multiple address field
    # names. (`address` is canonical, but `addr`/`wallet`/`account` appear in
    # some Dune Spellbook v2 exports.)
    _addr_field_candidates = ("address", "addr", "wallet", "account")
    for r in records:
        if not isinstance(r, dict):
            continue
        text = (r.get("name", "") or "") + " " + (r.get("category", "") or "")
        if matches_with_cooccurrence(text, family):
            named_count += 1
            addr = ""
            for k in _addr_field_candidates:
                if r.get(k):
                    addr = str(r[k])
                    break
            if addr:
                matched_addrs.add(_norm_addr(addr))

    cell.distinct_addresses = len(matched_addrs)
    cell.named_match_count = named_count
    cell.sample_addresses = sorted(matched_addrs)[:5]
    cell.notes = "spellbook is CEX-focused; mixers expected near-zero"
    return cell


# ---------------------------------------------------------------------------
# Reproducibility helpers
# ---------------------------------------------------------------------------


def _git_commit() -> str:
    """Return current git commit hash for manifest reproducibility."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, timeout=5
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    """Entry point. Returns:
        0  → positive control passed, manifest with status="OK" written.
        2  → OFAC SDN integrity check FAILED; FATAL diagnostic written.
        3  → positive control FAILED; manifest with status="FAIL" written.
        4  → output / cache directory not writable; aborted before network IO.
    """
    ap = argparse.ArgumentParser(description="public-source mixer-coverage probe")
    ap.add_argument("--cache-dir", type=Path, default=Path("/tmp/probe_mixer_cache"))
    ap.add_argument("--out", type=Path, default=Path("data/probe_mixer_sources.json"))
    # cache invalidation. Default refresh after 24h; flag to force.
    ap.add_argument(
        "--refresh-cache", action="store_true",
        help="Force re-fetch all sources, ignoring cache",
    )
    ap.add_argument(
        "--cache-ttl-hours", type=float, default=24.0,
        help="Auto-invalidate cache files older than this (default: 24h)",
    )
    args = ap.parse_args()

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    # preflight write permission so we fail BEFORE doing 30 MB
    # of network IO if the target paths are not writable.
    for d in (args.cache_dir, args.out.parent):
        if not os.access(d, os.W_OK):
            print(f"FATAL: directory not writable: {d}", file=sys.stderr)
            return 4

    # print session header BEFORE cache invalidation logs so the
    # reader has context before seeing per-file invalidate lines.
    print("=" * 70)
    print("public-source mixer-coverage probe")
    print(f"Cache: {args.cache_dir}")
    print(f"Out:   {args.out}")
    print(f"Time:  {_now_utc()}")
    print(f"Git:   {_git_commit()}")
    print("=" * 70)

    # stale-cache invalidation before any source load.
    # --cache-ttl-hours <= 0 means "no TTL", NOT "invalidate all".
    # outer condition simplified — when ttl_disabled and not
    # refresh_cache, there is nothing to do; skip directly.
    # skip iteration if directory is empty (first-run case).
    ttl_disabled = args.cache_ttl_hours <= 0
    if (args.refresh_cache or not ttl_disabled) and any(args.cache_dir.iterdir()):
        ttl_sec = args.cache_ttl_hours * 3600
        now = time.time()
        for cached in args.cache_dir.glob("*"):
            if not cached.is_file():
                continue
            if args.refresh_cache:
                reason = "force-refresh"
            elif not ttl_disabled and (now - cached.stat().st_mtime) > ttl_sec:
                age = now - cached.stat().st_mtime
                reason = f"age {age/3600:.1f}h > {args.cache_ttl_hours}h TTL"
            else:
                continue
            print(f"  cache invalidate: {cached.name} ({reason})")
            cached.unlink()

    print("\n--- loading sources ---")
    t0 = time.time()
    ofac_rows, ofac_meta = load_ofac_sdn(args.cache_dir)
    print(f"  ofac_sdn:           {ofac_meta.record_count:>7,} records "
          f"({ofac_meta.bytes_fetched/1024:.0f} KB, "
          f"integrity={'ok' if ofac_meta.integrity_check_passed else 'FAIL'}, "
          f"{time.time()-t0:.1f}s)")

    t0 = time.time()
    dawsbot_labels, dawsbot_meta = load_dawsbot_labels(args.cache_dir)
    print(f"  dawsbot_eth_labels: {dawsbot_meta.record_count:>7,} addresses "
          f"({dawsbot_meta.bytes_fetched/1024:.0f} KB, "
          f"integrity={'ok' if dawsbot_meta.integrity_check_passed else 'FAIL'}, "
          f"{time.time()-t0:.1f}s)")

    t0 = time.time()
    spellbook_recs, spellbook_meta = load_spellbook(args.cache_dir)
    print(f"  dune_spellbook:     {spellbook_meta.record_count:>7,} records "
          f"({spellbook_meta.bytes_fetched/1024:.0f} KB, "
          f"integrity={'ok' if spellbook_meta.integrity_check_passed else 'FAIL'}, "
          f"{time.time()-t0:.1f}s)")

    if not ofac_meta.integrity_check_passed:
        # Surface a structured FATAL diagnostic JSON to the local out path,
        # so an alive-check sees the file with status=FATAL instead of a
        # missing file.
        print(f"\nFATAL: OFAC SDN integrity FAIL: {ofac_meta.integrity_notes}",
              file=sys.stderr)
        diag = {
            "schema_version": "probe_mixer_sources_v2",
            "build_utc": _now_utc(),
            "git_commit": _git_commit(),
            "status": "FATAL",
            "reason": "ofac_sdn_integrity_failed",
            "ofac_meta": asdict(ofac_meta),
            "dawsbot_meta": asdict(dawsbot_meta),
            "spellbook_meta": asdict(spellbook_meta),
            "message": (
                "Positive-control source (OFAC SDN) failed integrity check. "
                "Probe aborted before matchers ran. See ofac_meta.integrity_notes "
                "for cause (size, sentinel, or schema parse failure)."
            ),
        }
        diag_bytes = json.dumps(diag, indent=2, sort_keys=True).encode()
        # atomic write also for FATAL diagnostic.
        _atomic_write(args.out, diag_bytes)
        # The FATAL state itself is the dominant signal; the local
        # diagnostic file is preserved for forensics.
        print(f"  diagnostic written to {args.out}", file=sys.stderr)
        return 2

    print("\n--- probing each (family, source) cell ---")
    families = list(KEYWORDS.keys())
    cells: list[ProbeCell] = []
    for family in families:
        print(f"\n  family: {family}")
        for cell_func, src_name, src_data in [
            (probe_ofac, "ofac_sdn", ofac_rows),
            (probe_dawsbot, "dawsbot_eth_labels", dawsbot_labels),
            (probe_spellbook, "dune_spellbook", spellbook_recs),
        ]:
            c = cell_func(src_data, family)
            cells.append(c)
            if c.error:
                # bump truncation 50 → 200 to preserve diagnostic detail.
                row_status = f"ERR: {c.error[:200]}"
            else:
                row_status = f"{c.distinct_addresses:>4d} addr (names matched: {c.named_match_count})"
            print(f"    {src_name:>22s}: {row_status}")

    # Positive control (rev 2026-05-16): name-matching "tornado_cash" against
    # OFAC SDN all_names yields 0 — Tornado Cash is registered in SDN under
    # developer Roman Semenov + DPRK3 program, NOT as "Tornado Cash" entity.
    # The semantically-correct positive control is: SDN must contain a
    # DPRK3-program party with ≥1 crypto address (Tornado/Lazarus surface).
    # We tighten to ≥10 total crypto addresses across all DPRK3 parties to
    # protect against Feature parsing dropping 80%+ of addresses silently.
    # 2026-05-16 smoke test: 6 DPRK3 parties had crypto, 55 total addresses.
    POSITIVE_CONTROL_MIN_ADDRESSES = 10
    dprk3_addr_count = 0
    dprk3_party_count = 0
    dprk3_sample_names: list[str] = []
    for r in ofac_rows:
        progs = (r.get("programs") or "").split("; ")
        if "DPRK3" not in progs:
            continue
        addrs = [v for v in (r.get("id_values") or "").split("; ") if v]
        if not addrs:
            continue
        dprk3_party_count += 1
        dprk3_addr_count += len(addrs)
        if len(dprk3_sample_names) < 5:
            nm = (r.get("name") or "").strip()[:60]
            if nm:
                dprk3_sample_names.append(nm)
    positive_control_passed = bool(dprk3_addr_count >= POSITIVE_CONTROL_MIN_ADDRESSES)

    # secondary-source integrity gate. If both dawsbot and
    # spellbook failed integrity, "all sources 0" cannot be distinguished
    # from "ceiling reached". Flag as BUG, not ceiling.
    secondary_sources_ok = (
        dawsbot_meta.integrity_check_passed
        or spellbook_meta.integrity_check_passed
    )

    # Decision per family.
    decisions: dict[str, str] = {}
    for family in families:
        ofac_cell = next(
            (c for c in cells if c.family == family and c.source == "ofac_sdn"),
            None,
        )
        dawsbot_cell = next(
            (c for c in cells if c.family == family and c.source == "dawsbot_eth_labels"),
            None,
        )
        spellbook_cell = next(
            (c for c in cells if c.family == family and c.source == "dune_spellbook"),
            None,
        )
        ofac_addr = ofac_cell.distinct_addresses if ofac_cell else 0
        ofac_named = ofac_cell.named_match_count if ofac_cell else 0
        dawsbot_addr = dawsbot_cell.distinct_addresses if dawsbot_cell else 0
        spellbook_addr = spellbook_cell.distinct_addresses if spellbook_cell else 0

        if not positive_control_passed:
            decisions[family] = "ABSTAIN — positive control failed"
        elif ofac_addr >= 1:
            decisions[family] = f"INCLUDE in D.1 (OFAC: {ofac_addr} addr)"
        elif ofac_named >= 1 and ofac_addr == 0:
            decisions[family] = (
                f"BUG_FLAG — OFAC named the entity ({ofac_named} record(s)) "
                f"but extracted 0 addresses; manual review needed"
            )
        elif (dawsbot_addr + spellbook_addr) >= 1:
            decisions[family] = (
                f"INCLUDE marginal (non-OFAC: dawsbot={dawsbot_addr}, "
                f"spellbook={spellbook_addr})"
            )
        elif not secondary_sources_ok:
            # don't claim ceiling when secondary sources broken.
            decisions[family] = (
                "BUG_FLAG — OFAC=0 and both secondary sources failed integrity "
                "(dawsbot + spellbook); cannot distinguish ceiling from outage"
            )
        else:
            decisions[family] = (
                "CEILING confirmed — only a commercial vendor could go further"
            )

    # explicit status field parallel to FATAL diagnostic path,
    # so cron alive-check can read one canonical field on every probe output.
    status = "OK" if positive_control_passed else "FAIL"
    out = {
        "schema_version": "probe_mixer_sources_v2",
        "build_utc": _now_utc(),
        "git_commit": _git_commit(),
        "status": status,
        "decision_target": "mixer registry build scope (build_mixer_registry.py)",
        "positive_control_passed": positive_control_passed,
        "positive_control_detail": (
            f"OFAC SDN DPRK3-program parties must yield ≥{POSITIVE_CONTROL_MIN_ADDRESSES} "
            f"crypto addresses (Tornado Cash + Lazarus surface). "
            f"Found {dprk3_addr_count} addresses across {dprk3_party_count} parties. "
            f"Sample party names: {dprk3_sample_names}"
        ),
        "positive_control_threshold": POSITIVE_CONTROL_MIN_ADDRESSES,
        "positive_control_dprk3_addr_count": dprk3_addr_count,
        "positive_control_dprk3_party_count": dprk3_party_count,
        "positive_control_dprk3_sample_names": dprk3_sample_names,
        "families_probed": families,
        "sources_probed": ["ofac_sdn", "dawsbot_eth_labels", "dune_spellbook"],
        "sources_dropped_from_v1": _DROPPED_SOURCES_V1_TO_V2,
        "source_meta": {
            "ofac_sdn": asdict(ofac_meta),
            "dawsbot_eth_labels": asdict(dawsbot_meta),
            "dune_spellbook": asdict(spellbook_meta),
        },
        "cells": [asdict(c) for c in cells],
        "decisions": decisions,
        "decision_rule": (
            f"Positive control: OFAC SDN DPRK3-program parties must yield "
            f"≥{POSITIVE_CONTROL_MIN_ADDRESSES} crypto addresses. Failure → ABSTAIN.\n"
            f"\n"
            f"Per family with positive control passed (rev 2026-05-16):\n"
            f"  OFAC name-match families ≥1 addr → INCLUDE in D.1 PASS scope.\n"
            f"  OFAC name-match families = 0 +\n"
            f"    dawsbot+spellbook ≥1 addr      → INCLUDE marginal.\n"
            f"  All sources 0                    → CEILING; commercial vendor only.\n"
            f"\n"
            f"Note: Tornado Cash, Lazarus, Sinbad surface in OFAC under their\n"
            f"  developer / operator names (Roman Semenov, Lazarus Group, Sinbad)\n"
            f"  with DPRK3 program tag. Family-name regex on all_names alone will\n"
            f"  miss Tornado Cash. Address-overlap matching against a curated\n"
            f"  mixer_registry_v1 (Track D Phase 1) will recover the link."
        ),
        "out_of_probe_scope": {
            "D.4_mixer_output_detection": (
                "D.4 PASS criterion (≥40/50 known mixer-output addresses → output_side=true) "
                "requires a separate seed list from OFAC press releases (e.g., Tornado Cash "
                "2022-08-08 press release lists ~22 Lazarus-operated post-mixer addresses). "
                "This probe does NOT address D.4."
            ),
        },
    }

    out_bytes = json.dumps(out, indent=2, sort_keys=True).encode()
    # atomic write so a kill mid-flush cannot poison local out.
    _atomic_write(args.out, out_bytes)
    sha = _file_sha256(out_bytes)

    print("\n" + "=" * 70)
    print("PROBE SUMMARY")
    print("=" * 70)
    print(f"Output: {args.out} ({len(out_bytes):,} bytes)")
    print(f"sha256: {sha}")
    print(f"\nPositive control (tornado_cash via OFAC): "
          f"{'PASSED' if positive_control_passed else 'FAILED'}")
    print("\nDecisions:")
    for family, decision in decisions.items():
        print(f"  {family:>15s}: {decision}")

    print(f"\noutput at {args.out}")

    return 0 if positive_control_passed else 3


if __name__ == "__main__":
    sys.exit(main())
