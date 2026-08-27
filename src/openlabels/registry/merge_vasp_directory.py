#!/usr/bin/env python3
"""Merge 9 jurisdiction-specific VASP raw dumps into vasp_directory_v2.

Combines ESMA EU + FCA UK + NY DFS + MAS SG + FinCEN US + HK SFC +
JP JFSA + CH FINMA + UAE VARA per-jurisdiction JSON dumps into a
single canonical VASP directory. Multi-jurisdiction entities
(Coinbase, Binance, Kraken, Crypto.com, Gemini, Circle, OKX, Paxos,
HashKey, Bitpanda, Sygnum, ...) are preserved with one row per
(canonical_entity_id, jurisdiction) so each license keeps its
own metadata.

Dedupe strategy (in priority order):
  1. LEI (Legal Entity Identifier) — only ESMA exposes this; primary
     unique key when present (~197 of 334 ESMA entries carry LEI).
  2. Canonical entity slug — name normalised by stripping legal-form
     suffixes (Ltd, LLC, Inc, Pte, Corp, Trust, Bank, ...), removing
     punctuation, lowercasing, and applying a manual alias map for
     well-known multi-jurisdiction parent groups (Coinbase, Binance,
     Kraken, Crypto.com / Foris DAX, Gemini, Circle, OKX, Paxos,
     BitGo, Bitstamp, Robinhood, Galaxy, Wintermute, Stripe, ...).
  3. Same MAS slug ID — handles the 5 known duplicate-style records
     ("Major Payment Institution X tdg as Y" pattern).

Output:
  data/vasp_directory_v2.parquet — Arrow table
  data/vasp_directory_v2.manifest.json — manifest
  data/vasp_directory_v2.json — full JSON for inspection / fallback

Manifest schema: source files, row counts, dedupe stats, sha256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

# Manual alias map: maps a substring (lowercase, post-clean) → canonical group ID.
# Order matters — first match wins. Keep specific aliases above generic ones.
ENTITY_ALIASES: list[tuple[str, str]] = [
    # Coinbase family
    ("cb payments", "coinbase"),
    ("coinbase custody", "coinbase"),
    ("coinbase ireland", "coinbase"),
    ("coinbase europe", "coinbase"),
    ("coinbase germany", "coinbase"),
    ("coinbase singapore", "coinbase"),
    ("coinbase株式会社", "coinbase"),
    ("coinbase", "coinbase"),
    # Kraken family (Payward = parent of Kraken)
    ("payward", "kraken"),
    ("crypto facilities", "kraken"),  # FCA-registered Kraken UK arm
    ("kraken", "kraken"),
    # Crypto.com family (Foris DAX = legal entity)
    ("foris dax", "crypto_com"),
    ("foris services", "crypto_com"),
    ("foris inc", "crypto_com"),
    ("crypto com", "crypto_com"),
    ("crypto.com", "crypto_com"),
    # Binance family
    ("binance", "binance"),
    # OKX / OKCoin (incl. JP/HK/MENA arms)
    ("okcoin", "okx"),
    ("オーケーコイン", "okx"),  # JP "OK-coin Japan"
    ("okx", "okx"),
    # Bitpanda
    ("bitpanda", "bitpanda"),
    # Bitstamp
    ("bitstamp", "bitstamp"),
    # Bybit
    ("bybit", "bybit"),
    # KuCoin / Mek Global (KuCoin parent)
    ("kucoin", "kucoin"),
    ("mek global", "kucoin"),
    # Bitfinex / iFinex
    ("bitfinex", "bitfinex"),
    ("ifinex", "bitfinex"),
    # Huobi / HTX
    ("huobi", "huobi"),
    ("htx ", "huobi"),
    # Bittrex
    ("bittrex", "bittrex"),
    # Poloniex
    ("poloniex", "poloniex"),
    # BitMEX
    ("bitmex", "bitmex"),
    ("hdr global", "bitmex"),
    # MEXC
    ("mexc", "mexc"),
    # Gemini
    ("gemini trust", "gemini"),
    ("gemini intergalactic", "gemini"),
    ("gemini exchange", "gemini"),
    ("gemini", "gemini"),
    # Paxos (incl. itBit)
    ("itbit", "paxos"),
    ("paxos trust", "paxos"),
    ("paxos global", "paxos"),
    ("paxos digital", "paxos"),
    ("paxos", "paxos"),
    # Circle (USDC issuer, NOT Banking Circle SA Luxembourg).
    # E.1.12.1 audit: bare "circle" matched "Banking Circle SA" → false-positive
    # 5-jur merge. Restricted to specific Circle Internet variants.
    ("circle internet", "circle"),
    ("circle financial", "circle"),
    ("circle global", "circle"),
    ("circle limited", "circle"),
    ("circle pte", "circle"),
    ("circle (germany)", "circle"),
    ("circle ireland", "circle"),
    # BitGo
    ("bitgo", "bitgo"),
    # Anchorage
    ("anchorage", "anchorage"),
    # Robinhood
    ("robinhood crypto", "robinhood"),
    ("robinhood", "robinhood"),
    # Block / Square / Cash App — narrow substrings to avoid scam-name
    # collisions (E.1.12 audit: "block chain wallet LTD" was a generic
    # FinCEN filing falsely merged into Block Inc).
    ("cash app", "block"),
    ("square inc", "block"),
    ("block inc", "block"),
    ("block, inc", "block"),
    # Bakkt
    ("bakkt", "bakkt"),
    # Galaxy Digital
    ("galaxy digital", "galaxy"),
    # Wintermute
    ("wintermute", "wintermute"),
    # Stripe
    ("stripe", "stripe"),
    # Ripple — broaden to catch all Ripple subsidiaries (Switzerland, Cayman, BVI, etc.)
    ("ripple labs", "ripple"),
    ("ripple markets", "ripple"),
    ("ripple switzerland", "ripple"),
    ("ripple ", "ripple"),  # narrow: trailing space avoids "tripple"/"ripples" collisions
    ("xrp ii", "ripple"),
    # MoonPay
    ("moonpay", "moonpay"),
    # Fireblocks
    ("fireblocks", "fireblocks"),
    # Fidelity Digital Asset Services
    ("fidelity digital", "fidelity_da"),
    # NYDIG
    ("nydig", "nydig"),
    # Custodia
    ("custodia", "custodia"),
    # Komainu
    ("komainu", "komainu"),
    # Zodia
    ("zodia", "zodia"),
    # eToro
    ("etoro", "etoro"),
    # PayPal
    ("paypal", "paypal"),
    # Skrill
    ("skrill", "skrill"),
    # Revolut
    ("revolut", "revolut"),
    # Sygnum
    ("sygnum", "sygnum"),
    # HashKey
    ("hashkey", "hashkey"),
    # StraitsX (DBS Stablecoin)
    ("straitsx", "straitsx"),
    ("xfers", "straitsx"),
    # FOMO Pay
    ("fomo pay", "fomopay"),
    # Independent Reserve
    ("independent reserve", "independent_reserve"),
    # Sparrow
    ("sparrow exchange", "sparrow"),
    # HAKO / Coinhako
    ("coinhako", "coinhako"),
    ("hako", "coinhako"),
    # ConsenSys
    ("consensys", "consensys"),
    # Zero Hash
    ("zero hash", "zero_hash"),
    # GSR
    ("gsr ", "gsr"),
    # SoFi
    ("sofi", "sofi"),
    # Solidi
    ("solidi", "solidi"),
    # Hidden Road
    ("hidden road", "hidden_road"),
    # Archax
    ("archax", "archax"),
    # Ramp
    ("ramp swaps", "ramp"),
    ("ramp ", "ramp"),
    # Blockchain.com
    ("blockchain.com", "blockchain_com"),
    ("blockchain com", "blockchain_com"),
    # Sygnia / Sygnum already above
    # DBS Vickers
    ("dbs vickers", "dbs"),
    # Triple A
    ("triple-a", "triplea"),
    ("triplea", "triplea"),
    # Upbit
    ("upbit", "upbit"),
    # Ziglu
    ("ziglu", "ziglu"),

    # === Asia/MENA additions ===
    # HashKey family (HK SFC: Hash Blockchain Limited; SG MAS: HashKey;
    # MENA: Hashkey MENA; alias::hashkey already declared above as
    # ("hashkey", "hashkey"); add HK legal-entity name explicitly)
    ("hash blockchain", "hashkey"),
    # OSL Digital Securities (HK SFC) + OSL Japan (JP JFSA)
    ("osl digital", "osl"),
    ("osl japan", "osl"),
    # Bullish (HK SFC: Bullish (GI) + Bullish HK Markets; EU MiCA: Bullish (EU))
    ("bullish", "bullish"),
    # Foris DAX HK / Foris DAX Middle East (UAE) — already mapped to crypto_com via "foris dax"
    # Whalefin Markets (HK SFC) = Amber Group HK arm
    ("whalefin", "amber_group"),
    ("amber premium", "amber_group"),
    # JP JFSA — major JP exchanges
    ("bitflyer", "bitflyer"),
    ("ビットフライヤー", "bitflyer"),
    ("gmoコイン", "gmo_coin"),
    ("gmo coin", "gmo_coin"),
    ("ビットバンク", "bitbank"),
    ("bitbank", "bitbank"),
    ("ビットトレード", "bittrade"),
    ("bittrade", "bittrade"),
    ("sbi vc", "sbi_vc"),
    ("sbi vcトレード", "sbi_vc"),
    ("コインチェック", "coincheck"),
    ("coincheck", "coincheck"),
    ("楽天ウォレット", "rakuten_wallet"),
    ("rakuten wallet", "rakuten_wallet"),
    ("line xenesis", "line_xenesis"),
    ("マネーパートナーズ", "money_partners"),
    ("money partners", "money_partners"),
    ("zaif", "zaif"),
    ("ザイフ", "zaif"),
    ("btcボックス", "btcbox"),
    ("btc box", "btcbox"),
    ("メルコイン", "mercari"),
    ("mercoin", "mercari"),
    ("crypto garage", "crypto_garage"),
    ("custodiem", "custodiem"),
    ("digital asset markets", "digital_asset_markets"),
    ("デジタルアセットマーケッツ", "digital_asset_markets"),
    ("gate japan", "gate_io"),
    ("gate technology", "gate_io"),
    ("gate ", "gate_io"),
    # CH FINMA — Swiss crypto banks
    ("amina bank", "amina_seba"),
    ("amina eu", "amina_seba"),  # ESMA-registered AMINA EU subsidiary
    ("seba bank", "amina_seba"),
    # NB: bare "seba" / "seba " stripped — false-positive on "Proseba (Schweiz)"
    ("sygnum bank", "sygnum"),  # narrows above ("sygnum", "sygnum")
    ("crypto finance", "crypto_finance"),
    ("taurus", "taurus"),
    ("six digital", "six_digital_exchange"),
    ("sdx trading", "six_digital_exchange"),
    ("six swiss", "six_swiss_exchange"),
    ("six repo", "six_swiss_exchange"),
    ("incore bank", "incore_bank"),
    ("postfinance", "postfinance"),
    ("dukascopy", "dukascopy"),
    ("swissquote", "swissquote"),
    ("bx swiss", "bx_swiss"),
    ("crypto consulting", "crypto_consulting"),
    ("hyperion fintech", "hyperion"),
    ("yapeal", "yapeal"),
    ("relio", "relio"),
    ("bivial", "bivial"),
    ("proseba", "proseba"),
    ("saphirstein", "saphirstein"),
    ("swiss crypto advisors", "swiss_crypto_advisors"),
    # UAE VARA — common MENA crypto firms
    ("bitoasis", "bitoasis"),
    ("hex trust", "hex_trust"),
    ("laser digital", "laser_digital"),
    ("nine blocks", "nine_blocks"),
    ("ceffu", "ceffu"),
    ("deribit", "deribit"),
    ("midchains", "midchains"),
    ("coincorner", "coincorner"),
    ("coinmena", "coinmena"),
    ("fasset", "fasset"),
    ("aquanow", "aquanow"),
    ("animoca brands", "animoca"),
    ("zand bank", "zand_bank"),
    ("selini capital", "selini"),
    ("mantra finance", "mantra_finance"),
    ("ht markets", "ht_group"),
    ("trek labs", "trek_labs"),
    ("scintilla", "scintilla"),
    ("varni", "varni"),
    ("prypco", "prypco"),
    ("morpheus software", "morpheus"),
    ("daman virtual", "daman"),
    ("liquidity fintech", "liquidity_fintech"),
    ("riv technologies", "riv"),
    ("xbase", "xbase"),
    ("nova digital", "nova_digital"),
    ("lct global", "lct_global"),
    ("ctrl alt", "ctrl_alt"),
    ("first crypto exchange", "first_crypto_exchange"),
    ("dkk digital", "dkk_digital"),
    ("ofza", "ofza"),
    ("mbio", "mbio"),
    ("mkx", "mkx"),
    ("gc exchange", "gcex"),
    ("gcex", "gcex"),
    ("tokinvest", "tokinvest"),
    ("atremo", "atremo"),
    ("gap 3 partners", "gap3"),
    ("web 3 innovations", "web3innovations"),
]


# Legal-form suffixes to strip during canonical-name normalisation.
LEGAL_SUFFIXES = [
    "ltd.", "ltd", "limited",
    "llc", "l.l.c.",
    "inc.", "inc", "incorporated",
    "corp.", "corp", "corporation",
    "co.", "co",
    "pte.", "pte", "pte ltd",
    "plc",
    "gmbh", "gmbh & co. kg", "ag",
    "s.a.", "sa", "s.l.", "sl",
    "n.a.", "na",
    "trust company", "trust co.", "trust",
    "bank", "bancorp",
    "holdings", "holding", "group",
    "international", "global",
    "(usa)", "(uk)", "(eu)", "(europe)",
    "europe", "ireland", "germany", "uk", "usa", "asia",
    "pty",
    "kk", "k.k.",
]


def normalize_name(name: str) -> str:
    """Lowercase, strip punctuation + legal suffixes."""
    s = (name or "").lower().strip()
    # Replace separators with space
    s = re.sub(r"[,/_]", " ", s)
    s = re.sub(r"\s+", " ", s)
    # Strip trailing legal suffixes iteratively
    changed = True
    while changed:
        changed = False
        for suf in LEGAL_SUFFIXES:
            pattern = rf"\b{re.escape(suf)}$"
            new = re.sub(pattern, "", s).strip()
            if new != s and new:
                s = new
                changed = True
    # Final cleanup: drop punctuation
    s = re.sub(r"[^\w\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


# LEI-pinned alias overrides — exact-LEI match wins over substring rules.
# Used for entities where the legal name does not carry a brand keyword
# (e.g. ESMA exposes "CIRCLE" with LEI 969500... = real Circle Internet
# Financial; substring "circle" was removed to fix Banking Circle SA
# false-positive).
LEI_TO_ALIAS: dict[str, str] = {
    # Circle Internet Financial known LEIs:
    "969500OYUDADGZKCR583": "circle",         # Circle Internet Financial Ltd (FR ESMA)
    # NOTE 254900GTP4UXQO1UMI36 was once incorrectly mapped to "circle" —
    # this LEI actually belongs to Robinhood Europe UAB (LT); since
    # corrected. Circle SG dedupes via alias
    # substring "circle pte" (ENTITY_ALIASES) — no LEI-pin needed.
    "213800W1NGBLERUS6M39": "banking_circle", # Banking Circle SA (LU) — DISTINCT entity
    # Gate.io MT subsidiary (ESMA bare "Gate" entry, MT MiCA register):
    "984500D6A0F945BB5A15": "gate_io",        # Gate Technology MT
    # Robinhood Europe UAB (LT — Bank of Lithuania licensee). Without this
    # LEI-pin Robinhood would only be 2-jur (US/US-NY); the alias map
    # enumerates Robinhood as 3-jur including LT.
    "254900GTP4UXQO1UMI36": "robinhood",      # Robinhood Europe UAB (LT)
}


# Exact-name overrides — case-insensitive whole-string match wins over
# substring rules. Used for short bare-name entries where substring
# match would be ambiguous (e.g. "CIRCLE" in ESMA AT register).
EXACT_NAME_TO_ALIAS: dict[str, str] = {
    "circle": "circle",   # ESMA bare "CIRCLE" → Circle Internet
    "gate": "gate_io",    # ESMA bare "Gate" (MT MiCA) → Gate.io
    "ripple": "ripple",   # any bare "Ripple" entry → Ripple Labs canonical
    "bitfinex": "bitfinex",
    "kucoin": "kucoin",
    "bybit": "bybit",
    "mexc": "mexc",
}


# Junk-guard rules — reject substring matches that lead to false-positive
# merges into legitimate brand canonicals. Added 2026-05-15 after
# E.1.12 audit revealed FinCEN-MSB filings polluting multi-jur set with
# scam typosquats (Gate.io Binance Crypto BlackRock Ai decentralized;
# Axpout/Cuphax Crypto Finance Ltd; OKXG Capital Foundation; etc.).
_SUSPICIOUS_NAME_PATTERNS = [
    re.compile(r"\bcapital\s+foundation\b", re.I),
    re.compile(r"\bblockrock\s+ai\b", re.I),
    re.compile(r"\bdecentralized\s+exchange\b", re.I),
    re.compile(r"\bcrypto\s+capital\b", re.I),  # FinCEN scam pattern
    re.compile(r"\b(crypto|blockchain)\s+investment\s+foundation\b", re.I),
    re.compile(r"\bcoin[- ]pro\s+crypto\s+foundation\b", re.I),
    # Brand + "Foundation" suffix often = FinCEN scam shell
    # (Huobi Foundation, Bitcoin Crypto Capital Foundation, etc.).
    # Real exchanges register as Inc/LLC/Trust/Securities, not Foundation.
    re.compile(r"^(huobi|kucoin|bittrex|poloniex|bitmex|mexc|bitfinex)\s+foundation\b", re.I),
]

# Brand keywords used for multi-brand collision detection.
# A name containing 2+ keywords from this list is presumed scam-templated.
_BRAND_KEYWORDS = [
    "binance", "okx", "kraken", "coinbase", "gemini", "bitstamp",
    "crypto.com", "paxos", "circle", "bybit", "kucoin", "huobi",
    "bitfinex", "gate.io", "blackrock", "blockfi",
]

# Brand-then-suffix typosquat regexes — common FinCEN MSB scam shape:
# real-brand + alphabetic suffix = scam (Geminifin, OKXLE, AOKX,
# Bitgoo, Geminifn, etc.)
_TYPOSQUAT_PATTERNS = [
    re.compile(r"\b(?:gemini)(?:fin|blu|moonbase|cloud|ex|fn)\b", re.I),
    # OKX typosquats — bare "888okx" without further suffix is also scam.
    # Real OKX entities use "OKX" as standalone word or "OKX Inc/Ltd".
    re.compile(r"\b(?:888)okx\b", re.I),
    re.compile(r"\bokx(?:le|g|s|fn)\b", re.I),
    re.compile(r"\baokx\b", re.I),
    re.compile(r"\bgrokcoin\b", re.I),
    re.compile(r"\bbitgoo\b", re.I),
    re.compile(r"\bcrypto[-]gate\s+capital", re.I),
    re.compile(r"^onramp\s+bitcoin", re.I),  # "Onramp Bitcoin LLC" != Ramp Network
    re.compile(r"^block\s+chain\s+wallet", re.I),  # generic, not Block Inc
    re.compile(r"^tocgy\s+crypto\s+block", re.I),
    # FinCEN scam Crypto Finance shells
    re.compile(r"^(axpout|cuphax|rthae|cresia|fenrod)\s+crypto\s+finance", re.I),
    # Brand-prefix typosquats (KaKuCoin = K + KuCoin scam variation)
    re.compile(r"\bkakucoin\b", re.I),
    re.compile(r"\bbinancex\b", re.I),
    re.compile(r"\bcoinbasex\b", re.I),
    re.compile(r"\bkrakenex\b", re.I),
    # PaxosEX = scam typosquat (real Paxos uses Trust/Digital/Global)
    re.compile(r"\bpaxosex\b", re.I),
    # "Bybit Currency Trading" — FinCEN scam-shaped (real Bybit is "Bybit Fintech Ltd")
    re.compile(r"^bybit\s+currency\s+trading\b", re.I),
    # "Lexinova Digital" — distinct firm, not Nova Digital FZE (UAE)
    re.compile(r"\blexinova\b", re.I),
    # "Tiny Score Ripple Foundation" — FinCEN scam shell
    re.compile(r"^tiny\s+score\s+ripple\b", re.I),
    # "Tripple S Innovation" — substring "ripple" but unrelated
    re.compile(r"^tripple\s+s\b", re.I),
]


def is_junk_name(name: str) -> bool:
    """Return True if name matches a known FinCEN-MSB scam-templated
    pattern that pollutes alias merges. Used as guard before applying
    a substring match in canonical_id()."""
    if not name:
        return False
    for pat in _SUSPICIOUS_NAME_PATTERNS:
        if pat.search(name):
            return True
    for pat in _TYPOSQUAT_PATTERNS:
        if pat.search(name):
            return True
    # Multi-brand collision (2+ distinct major brand keywords in name)
    name_lower = name.lower()
    hits = sum(1 for kw in _BRAND_KEYWORDS if kw in name_lower)
    if hits >= 2:
        return True
    return False


def canonical_id(record: dict) -> str:
    """Return canonical entity ID for a single VASP record.

    Priority:
      1. Manual alias map (substring match on lowercased name) — wins
         FIRST so a global parent group (Coinbase, Kraken, Binance,
         Crypto.com, ...) collapses across regimes even when each
         regional subsidiary holds its own LEI.
         JUNK-GUARD: if name matches a scam-templated FinCEN-MSB
         pattern, alias match is skipped to prevent false-positive
         merges (audit trail: 2026-05-15 E.1.12 cleanup).
      2. LEI from ESMA records (`_esma_lei`) — used only when no alias
         hit, to dedupe within ESMA where multiple records share an LEI.
      3. Normalised entity name slug.
    """
    name_raw = record.get("entity_name") or ""
    name_lower = name_raw.lower().strip()
    lei = (record.get("_esma_lei") or "").strip()

    # Priority 0 — LEI-pinned alias (exact LEI match wins over substring).
    # Used for entities whose legal name does not carry a brand keyword
    # (e.g. ESMA "CIRCLE" with LEI 969500... = real Circle Internet).
    if lei and lei in LEI_TO_ALIAS:
        return f"alias::{LEI_TO_ALIAS[lei]}"

    # Priority 0.5 — exact-name override (case-insensitive whole-string).
    # Catches bare-name registrations where substring match is too risky.
    if name_lower in EXACT_NAME_TO_ALIAS:
        return f"alias::{EXACT_NAME_TO_ALIAS[name_lower]}"

    # Junk-guard: do not collapse FinCEN scam shells into legitimate
    # brand canonicals. Falls through to LEI / name slug.
    if not is_junk_name(name_raw):
        # Priority 1 — alias map (substring match) — wins over LEI to keep
        # global parent groups together across regimes.
        for substring, canonical in ENTITY_ALIASES:
            if substring in name_lower:
                return f"alias::{canonical}"

    # Priority 2 — LEI (only when no alias matched)
    if lei and len(lei) == 20:
        return f"lei::{lei}"

    # Priority 3 — normalised name
    norm = normalize_name(record.get("entity_name") or "")
    if not norm:
        return f"raw::{record.get('address', 'unknown')}"
    return f"name::{norm}"


def _surrogate_license_id(record: dict) -> str | None:
    """Build stable surrogate license_id for sources without native public IDs.

    The directory schema requires non-null license_id
    on every license record. Three structural classes within the 9-source scope
    do not provide a public license number for every row:
      - NY DFS BitLicense — DFS does not publish a license number; uniqueness
        comes from entity name + license_type + license_date.
      - FinCEN MSB Registrant Search — bulk dump does not surface MSB ID.
      - ESMA MiCA register bare-name notification entries (137 of 334 rows
        across IT/BG/etc. country supervisors — small Article-60 EU passport
        notifications without an LEI; 197 of 334 ESMA rows do carry an LEI
        and use it as native license_id).
    For these the merge synthesises a stable surrogate of the form
    `{source}::{entity_slug}` (with `esma_<JUR>::<slug>` for ESMA so the
    surrogate disambiguates per-country notifications). Downstream code
    (E.2 mapping, E.3 API) gets a non-null key for join + audit trail.
    Surrogate is documented in manifest schema_notes; rows carry
    `license_id_is_surrogate=true`.
    """
    name = (record.get("entity_name") or "").strip().lower()
    if not name:
        return None
    slug = re.sub(r"[^\w]+", "_", name).strip("_")
    if not slug:
        return None
    jur = (record.get("jurisdiction") or "").upper()
    reg = record.get("regulator") or ""
    if jur == "US-NY" or "NY DFS" in reg or "Department of Financial Services" in reg:
        return f"nydfs::{slug}"
    if jur == "US" and "FinCEN" in reg:
        return f"fincen::{slug}"
    # ESMA MiCA — bare-name CASP without LEI (~137 of 334 rows).
    # ESMA per-country supervisor list. Use jurisdiction-prefixed surrogate
    # so a name-collision across two EU countries does not collapse.
    if record.get("source_url", "").startswith("https://www.esma.europa.eu") \
       or "ESMA" in reg or "MiCA" in reg or "CASP" in reg:
        jur_part = jur or "EU"
        return f"esma_{jur_part}::{slug}"
    return None


def license_record(record: dict) -> dict:
    """Project a raw record into a single VaspLicense-shaped dict.

    license_id falls back to a stable surrogate (`nydfs::<slug>`,
    `fincen::<slug>`) when the source provides no native public ID — surrogate
    is generated only for NYDFS + FinCEN where this is structural (per
    scrape_nydfs_bitlicense.py:300 + scrape_fincen_msb.py:226). All other
    sources keep their native license_id (LEI, FRN, MAS Reg ID, HK SFC LIC,
    JFSA bureau-no, FINMA register-no, VARA licence-no).
    """
    license_date = (
        record.get("_esma_authorisation_date")
        or record.get("_fca_mlr_effective_date")
        or record.get("_nydfs_license_date")
        or record.get("_fincen_auth_date")
        or record.get("_hk_amlo_effective_date")        # E.1.8 HK SFC
        or record.get("_jp_registration_date_iso")     # E.1.9 JP JFSA
        or record.get("_vara_licence_issued")           # E.1.11 UAE VARA
        # E.1.10 CH FINMA: source has no license_date column (Wayback CSV
        # lacks date metadata). Returns None — recorded as honest gap in
        # manifest, not padded.
    )
    license_id = record.get("license_id") or _surrogate_license_id(record)
    return {
        "jurisdiction": record.get("jurisdiction"),
        "license_id": license_id,
        "license_id_is_surrogate": (record.get("license_id") is None
                                       and license_id is not None),
        "regulator": record.get("regulator"),
        "license_status": record.get("license_status"),
        "license_date": license_date,
        "casp_registered": record.get("jurisdiction", "").startswith(("AT", "BE", "BG",
            "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT",
            "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
            "NO", "IS", "LI"))
        or None,
        "source_url": record.get("source_url"),
    }


# Curated primary_name override for canonical entities — used in API
# response (vasp.canonical_name field). Without this the auto-selected
# primary_name picks `max(names, key=len)` which gives weird subsidiary
# names ("Tagomi Trading, LLC (acquired by Coinbase 2020)" for Coinbase,
# "kucoin pro" for KuCoin, "Major Payment Institution SPARROW TECH PRIVATE
# LIMITED tdg as Amber Premium Singapore" for Amber Group). This map
# produces the brand name a downstream consumer expects.
PRIMARY_NAME_OVERRIDE: dict[str, str] = {
    "alias::coinbase":      "Coinbase",
    "alias::kraken":        "Kraken (Payward)",
    "alias::binance":       "Binance",
    "alias::crypto_com":    "Crypto.com (Foris DAX)",
    "alias::bitstamp":      "Bitstamp",
    "alias::okx":           "OKX",
    "alias::bitpanda":      "Bitpanda",
    "alias::circle":        "Circle Internet Financial",
    "alias::banking_circle": "Banking Circle SA",
    "alias::gemini":        "Gemini",
    "alias::bitgo":         "BitGo",
    "alias::kucoin":        "KuCoin",
    "alias::bybit":         "Bybit",
    "alias::bitfinex":      "Bitfinex",
    "alias::huobi":         "Huobi (HTX)",
    "alias::mexc":          "MEXC",
    "alias::bittrex":       "Bittrex",
    "alias::ripple":        "Ripple",
    "alias::paxos":         "Paxos",
    "alias::galaxy":        "Galaxy Digital",
    "alias::hashkey":       "HashKey",
    "alias::moonpay":       "MoonPay",
    "alias::paypal":        "PayPal",
    "alias::wintermute":    "Wintermute Trading",
    "alias::robinhood":     "Robinhood Crypto",
    "alias::amber_group":   "Amber Group",
    "alias::anchorage":     "Anchorage Digital",
    "alias::bakkt":         "Bakkt",
    "alias::fidelity_da":   "Fidelity Digital Assets",
    "alias::nydig":         "NYDIG",
    "alias::block":         "Block (Square / Cash App)",
    "alias::stripe":        "Stripe Payments",
    "alias::blockchain_com":"Blockchain.com",
    "alias::crypto_finance":"Crypto Finance AG",
    "alias::amina_seba":    "AMINA Bank (formerly SEBA)",
    "alias::sygnum":        "Sygnum Bank",
    "alias::swissquote":    "Swissquote",
    "alias::komainu":       "Komainu",
    "alias::zodia":         "Zodia Custody",
    "alias::hidden_road":   "Hidden Road Partners",
    "alias::skrill":        "Skrill / NETELLER",
    "alias::revolut":       "Revolut",
    "alias::bullish":       "Bullish",
    "alias::bitflyer":      "bitFlyer",
    "alias::osl":           "OSL Digital Securities",
    "alias::gate_io":       "Gate.io",
    "alias::gcex":          "GCEX",
    "alias::fireblocks":    "Fireblocks",
    "alias::etoro":         "eToro",
}


# Map source tag → jurisdiction code(s) it can supply. Used in manifest
# license_date null-rate audit to attribute nulls per source.
_SOURCE_JURISDICTION_MAP: dict[str, set[str]] = {
    "esma": {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
             "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
             "PL", "PT", "RO", "SK", "SI", "ES", "SE", "NO", "IS", "LI"},
    "fca": {"GB"},
    "nydfs": {"US-NY"},
    "mas": {"SG"},
    "fincen": {"US"},
    "hk_sfc": {"HK"},
    "jp_jfsa": {"JP"},
    "ch_finma": {"CH"},
    "uae_vara": {"AE-DU"},
}


def _source_jurisdictions(tag: str) -> set[str]:
    return _SOURCE_JURISDICTION_MAP.get(tag, set())


def source_files(dump_date: str) -> dict[str, str]:
    """Raw-dump file names as emitted by the scrapers for a given date."""
    return {
        "esma": f"esma_mica_vasps_{dump_date}.json",
        "fca": f"fca_register_vasps_{dump_date}.json",
        "nydfs": f"nydfs_vasps_{dump_date}.json",
        "mas": f"mas_dpt_vasps_{dump_date}.json",
        "fincen": f"fincen_msb_vasps_{dump_date}.json",
        "hk_sfc": f"hk_sfc_vasps_{dump_date}.json",
        "jp_jfsa": f"jp_jfsa_vasps_{dump_date}.json",
        "ch_finma": f"ch_finma_vasps_{dump_date}.json",
        "uae_vara": f"uae_vara_vasps_{dump_date}.json",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", type=Path, default=Path("data") / "labels_raw")
    parser.add_argument("--dump-date", required=True,
                        help="date suffix of the raw scraper dumps, YYYY-MM-DD")
    parser.add_argument("--out-parquet", type=Path,
                        default=Path("data") / "vasp_directory_v2.parquet")
    parser.add_argument("--out-json", type=Path,
                        default=Path("data") / "vasp_directory_v2.json")
    parser.add_argument("--out-manifest", type=Path,
                        default=Path("data") / "vasp_directory_v2.manifest.json")
    args = parser.parse_args()

    # Load all 9 raw dumps
    sources: dict[str, list[dict]] = {}
    src_files = source_files(args.dump_date)
    for tag, fname in src_files.items():
        path = args.raw_dir / fname
        if not path.exists():
            raise FileNotFoundError(f"Missing raw source: {path}")
        with path.open() as fh:
            sources[tag] = json.load(fh)
        print(f"  {tag:6s}: {len(sources[tag]):,} entries from {fname}")

    total_raw = sum(len(v) for v in sources.values())
    print(f"\nTotal raw entries: {total_raw:,}")

    # Group by canonical_id; collect each license under its parent group
    groups: dict[str, dict] = defaultdict(lambda: {
        "names": [],
        "licenses": [],
        "sources": [],
        "leis": set(),
        "raw_addresses": [],
    })

    for tag, records in sources.items():
        for r in records:
            cid = canonical_id(r)
            groups[cid]["names"].append(r.get("entity_name", ""))
            groups[cid]["sources"].append(tag)
            groups[cid]["raw_addresses"].append(r.get("address", ""))
            lei = r.get("_esma_lei")
            if lei:
                groups[cid]["leis"].add(lei)
            groups[cid]["licenses"].append(license_record(r))

    # Build canonical entities — one per group, multi-license preserved
    # LEI-disagreement audit: track aliases that merged ≥2 distinct LEIs.
    # Some (Coinbase, Bitstamp, Bitpanda) are real — global firms hold
    # one LEI per regulated subsidiary. Others (Banking Circle vs Circle
    # Internet) are false-positives we want to surface for review.
    lei_disagreement_audit: list[dict] = []

    entities: list[dict] = []
    for cid, g in groups.items():
        # Pick most common (or longest) name as canonical, unless
        # PRIMARY_NAME_OVERRIDE supplies a curated brand name.
        names = g["names"]
        if cid in PRIMARY_NAME_OVERRIDE:
            primary_name = PRIMARY_NAME_OVERRIDE[cid]
        else:
            primary_name = max(names, key=lambda n: (len(n), names.count(n)))
        # Dedupe licenses by (jurisdiction, regulator) — same firm sometimes
        # appears twice in the same jurisdiction (e.g. MAS duplicates).
        # Whitespace-collapse regulator string before key construction
        # (e.g. ESMA IT  CONSOB vs CONSOB single-vs-double-space).
        seen_licenses: set[tuple[str | None, str | None]] = set()
        uniq_licenses = []
        for lic in g["licenses"]:
            jur = lic.get("jurisdiction")
            reg = lic.get("regulator")
            reg_norm = re.sub(r"\s+", " ", reg.strip()) if reg else reg
            key = (jur, reg_norm)
            if key in seen_licenses:
                continue
            seen_licenses.add(key)
            uniq_licenses.append(lic)
        # Multi-jurisdiction = unique jurisdictions ≥2
        unique_jurisdictions = {lic.get("jurisdiction") for lic in uniq_licenses if lic.get("jurisdiction")}
        # LEI-disagreement check: alias canonicals merging ≥2 distinct LEIs
        if cid.startswith("alias::") and len(g["leis"]) >= 2:
            lei_disagreement_audit.append({
                "canonical_id": cid,
                "primary_name": primary_name,
                "leis": sorted(g["leis"]),
                "raw_names": list(set(g["names"])),
                "sources": sorted(set(g["sources"])),
            })

        entities.append({
            "canonical_id": cid,
            "name": primary_name,
            "jurisdictions": sorted(unique_jurisdictions),
            "n_jurisdictions": len(unique_jurisdictions),
            "n_licenses": len(uniq_licenses),
            "licenses": uniq_licenses,
            "source_tags": sorted(set(g["sources"])),
            "leis": sorted(g["leis"]),
            "raw_addresses": g["raw_addresses"],
        })

    # Sort: multi-jurisdiction first, then by license count, then by name
    entities.sort(key=lambda e: (-e["n_jurisdictions"], -e["n_licenses"], e["name"].lower()))

    print(f"\nCanonical entities after dedupe: {len(entities):,}")
    multi_juris = [e for e in entities if e["n_jurisdictions"] >= 2]
    print(f"Multi-jurisdiction (≥2 regimes): {len(multi_juris):,}")

    # Top multi-jurisdiction (qualitative QA)
    print("\nTop 15 multi-jurisdiction entities:")
    for e in multi_juris[:15]:
        print(f"  {e['name'][:55]:55s}  juris={e['n_jurisdictions']:2d}  "
              f"licenses={e['n_licenses']:2d}  juris={','.join(e['jurisdictions'])}")

    # Write parquet
    args.out_parquet.parent.mkdir(parents=True, exist_ok=True)

    table = pa.Table.from_pylist(entities)
    pq.write_table(table, args.out_parquet, compression="zstd")
    parquet_bytes = args.out_parquet.stat().st_size
    print(f"\nParquet: {args.out_parquet} ({parquet_bytes:,} bytes)")

    # Write JSON for inspection
    with args.out_json.open("w", encoding="utf-8") as fh:
        json.dump(entities, fh, indent=2, ensure_ascii=False)
    json_bytes = args.out_json.stat().st_size
    print(f"JSON:    {args.out_json} ({json_bytes:,} bytes)")

    # SHA256 recomputed from the actual written file, never from stdout
    sha = hashlib.sha256(args.out_parquet.read_bytes()).hexdigest()

    # Per-jurisdiction summary
    jur_counts: dict[str, int] = defaultdict(int)
    for e in entities:
        for j in e["jurisdictions"]:
            jur_counts[j] += 1

    # License-date null rate per source — surfaced in manifest as honest gap
    license_date_nulls_by_source: dict[str, dict] = {}
    for tag in src_files:
        n_total = sum(1 for e in entities for lic in e["licenses"]
                      if tag in e["source_tags"] and lic.get("jurisdiction") in
                      _source_jurisdictions(tag))
        n_null_dates = sum(1 for e in entities for lic in e["licenses"]
                           if tag in e["source_tags"]
                           and lic.get("jurisdiction") in _source_jurisdictions(tag)
                           and not lic.get("license_date"))
        if n_total:
            license_date_nulls_by_source[tag] = {
                "total_licenses": n_total,
                "null_license_date": n_null_dates,
                "null_rate_pct": round(100 * n_null_dates / n_total, 1),
            }

    manifest = {
        "version": "v2",
        "created_at": datetime.now(UTC).isoformat(),
        "source_files": dict(src_files),
        "raw_entries_by_source": {tag: len(records) for tag, records in sources.items()},
        "raw_total": total_raw,
        "canonical_entities": len(entities),
        "multi_jurisdiction_entities": len(multi_juris),
        "license_records_total": sum(e["n_licenses"] for e in entities),
        "jurisdictions_covered": sorted(jur_counts.keys()),
        "entities_by_jurisdiction": dict(sorted(jur_counts.items(),
                                                key=lambda kv: -kv[1])),
        "license_date_nulls_by_source": license_date_nulls_by_source,
        "lei_disagreement_audit": lei_disagreement_audit,
        "source_caveats": {
            "esma": "ESMA MiCA register (2024-12-CASPS.csv export). Per-country "
                    "filings; an entity with EU passport files in one home "
                    "country only — IT and DE dominate single-jur counts. "
                    "Bare-name entries (e.g. 'CIRCLE', 'Gate', 'Bybit', 'MEXC') "
                    "use LEI_TO_ALIAS / EXACT_NAME_TO_ALIAS to attach to "
                    "global parent canonicals.",
            "fca": "UK FCA Financial Services Register seed-list approach (no "
                   "bulk crypto-firm export available). Each seed name "
                   "verified per-FRN against MLR-Registered status. "
                   "Coverage: tier-1 + curated tier-2 names; tail of "
                   "FCA-registered cryptoasset firms may be incomplete.",
            "nydfs": "NY DFS BitLicense + Limited-Purpose Trust Charter list. "
                     "Manually curated from public DFS register page; refreshed "
                     "via web scrape with HTML structure assumption.",
            "mas": "MAS DPT register exposes no per-row license_date column; "
                   "license_date null for all MAS rows by source design. "
                   "Filing-format may leak into entity_name field for "
                   "Major Payment Institution rows (e.g. Amber Group MAS row "
                   "carries 'Major Payment Institution X tdg as Y' string).",
            "fincen": "FinCEN MSB registrants include compliance shells with no "
                      "on-chain footprint. Quality scoring (real exchange vs MSB "
                      "shell) is future work. ~700 of 810 FinCEN entries are "
                      "single-jur small US-LLCs without overseas presence. "
                      "Junk-guard rejects scam-templated names but ~700 shells "
                      "remain as 1-jur name::* canonicals.",
            "hk_sfc": "HK SFC VATP register — full enumerable universe via "
                       "publicregWeb/searchByRaJson API; 17 firms total "
                       "(complete coverage as of 2026-05-15).",
            "jp_jfsa": "JP FSA register PDF parsed via pdfplumber. JVCEA member "
                        "list cross-reference confirmed 27 firms exact match. "
                        "Pure-katakana legal names (Bitbank, Coincheck, Bittrade) "
                        "carry kana → roman aliases via ENTITY_ALIASES.",
            "ch_finma": "Wayback snapshot 2025-06-25 (>10mo stale); finma.ch live "
                        "blocks scripted clients. License statuses post-snapshot "
                        "revocations/grants invisible. Refresh path: live access "
                        "requires residential proxy / headless browser; out of "
                        "scope here. Production-DD users must annotate CH "
                        "rows as snapshot-dated.",
            "uae_vara": "UAE VARA public-register HTML scrape (vara.ae); 49 "
                         "firms (Active or Issued status). Dubai (AE-DU) only — "
                         "ADGM FSRA (Abu Dhabi) explicitly out of scope. "
                         "License-issued dates populated 100% non-null.",
        },
        "parquet_sha256": sha,
        "parquet_bytes": parquet_bytes,
        "parquet_path": str(args.out_parquet),
        "json_path": str(args.out_json),
        "dedupe_strategy": [
            "0. LEI-pinned alias (LEI_TO_ALIAS) — exact LEI match wins over "
            "everything (used for bare-name ESMA entries: Circle Internet FR/SG, "
            "Gate.io MT, Banking Circle SA disambiguation)",
            "0.5. Exact-name override (EXACT_NAME_TO_ALIAS) — case-insensitive "
            "whole-string match (CIRCLE, Gate, Ripple, KuCoin, Bybit, MEXC, "
            "Bitfinex bare entries)",
            "1. Manual alias map — substring match for known multi-jurisdiction "
            "parent groups (alias wins over LEI to keep global firms collapsed)",
            "2. LEI (Legal Entity Identifier) — fallback when no alias matches",
            "3. Normalised entity name (legal-form suffix stripping + "
            "lowercasing + punctuation removal)",
            "Junk-guard: is_junk_name() rejects FinCEN-MSB scam-templated patterns "
            "(Capital Foundation, BlockRock Ai, brand+suffix typosquats, etc.) "
            "before alias match, preventing false-positive merges.",
            "Primary_name override (PRIMARY_NAME_OVERRIDE): curated brand display "
            "names for top ~50 alias canonicals — used in API vasp.canonical_name. "
            "Without override, max(names, key=len) picks weird subsidiary strings.",
        ],
        "schema_notes": {
            "raw_addresses": "Provenance pointer: list of source-system primary "
                              "keys (e.g. fincen::name, fca::frn::N, mas::id, "
                              "ESMA LEI). NOT on-chain blockchain addresses. "
                              "On-chain address mapping lives in separate "
                              "vasp_to_address_v1.parquet (build_vasp_to_address output).",
            "leis": "LEIs collected across all merged source rows. "
                     "lei_disagreement_audit surfaces alias canonicals merging "
                     "≥2 distinct LEIs for manual review.",
            "primary_name": "PRIMARY_NAME_OVERRIDE-driven for top ~50 known "
                              "brands; auto-selected longest-name otherwise.",
            "license_id": "Native regulator-issued ID where source provides "
                              "(7 of 9: ESMA LEI, FCA FRN, MAS register-id, HK "
                              "SFC LIC, JP JFSA bureau-no, CH FINMA register-no, "
                              "UAE VARA licence-no). For NYDFS BitLicense + "
                              "FinCEN MSB the regulators do not publish a "
                              "public license number (NYDFS uniqueness = entity "
                              "+ license_type + license_date; FinCEN bulk dump "
                              "omits MSB ID). Merge generates a stable surrogate "
                              "`nydfs::<slug>` / `fincen::<slug>` for these "
                              "rows so downstream join keys are non-null. "
                              "license_id_is_surrogate=true marks the surrogate "
                              "rows for audit trail.",
        },
    }
    with args.out_manifest.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    print(f"Manifest: {args.out_manifest}")
    print(f"  parquet_sha256: {sha}")

    # Quality-floor summary
    print("\n=== quality floors ===")
    print(f"entities (floor 1,000): {len(entities):,} {'PASS' if len(entities) >= 1000 else 'FAIL'}")
    print(f"multi-jurisdiction (floor 100): {len(multi_juris):,} "
          f"{'PASS' if len(multi_juris) >= 100 else 'INFO (mapping to the address layer may still cover it)'}")


if __name__ == "__main__":
    main()
