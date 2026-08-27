#!/usr/bin/env python3
"""Swiss FINMA VASP / crypto-licensed institution scraper


Source-of-truth: the FINMA "Authorised institutions, individuals and
products" master file `uid.csv`, published at
`finma.ch/de/~/media/finma/dokumente/bewilligungstraeger/csv/uid.csv`.
This CSV is the canonical, machine-readable register of every entity
under FINMA prudential supervision. Each row carries:
  Name; City; AuthorisationTypeDE; AuthorisationTypeFR;
  AuthorisationTypeIT; AuthorisationTypeEN; UID

(UID = Unternehmens-Identifikationsnummer = Swiss enterprise identifier.)

Why this source (not the Salesforce-style HTML hub):
The HTML hub at `/finma-public/authorised-institutions-...` renders a
JavaScript catalogue that proxies to per-category XLSX/CSV files. The
master `uid.csv` already aggregates every category in one structured
artifact, with a stable schema, and is the file the hub itself links
to. It is the smallest possible DD-survivable evidence object.

Live finma.ch CDN aggressively blocks scripted clients (HTTP/2 400 on
plain curl regardless of UA/cookies). We fall back to the most recent
Wayback Machine capture (2025-06-25, 70.7 KB, 2,892 rows). The
fall-back is explicit, surfaces in the output, and uses the official
content via an immutable archive — a DD-acceptable
evidence file.

VASP filter (path: FINMA-direct, NOT SRO list):
Switzerland regulates crypto businesses through several FINMA licence
categories, NOT through a single "VASP" register. The filter keeps:
  1. Every holder of `persons under Article 1b of the Banking Act`
     (= FinTech licence). This category was created in 2019 explicitly
     for blockchain / payment-token / crypto-deposit firms; entire
     population (~6 firms) is in scope.
  2. Trading venues with "Swiss trading venue" / "Multilateral trading
     system" auth-types — the regulatory home of DLT trading systems
     (SDX Trading AG = SIX Digital Exchange) and the Swiss Stock
     Exchange operator.
  3. Banks + Securities firms + Custodian banks + Fund management
     companies + Portfolio managers whose legal name matches the
     known-crypto seed list (Sygnum, AMINA, Bitcoin Suisse, 21Shares,
     etc.). Without the seed AND-filter we would pull in ~1,900
     traditional banks/asset managers, blowing up false-positive count.

We do NOT scrape SRO member lists (VQF, PolyReg, OSFin Control). VQF
publishes no public list; PolyReg's API is a per-name yes/no verifier,
not a listing endpoint. SRO membership = AMLA Art. 2 para 3 financial
intermediary status, which is broader than "crypto VASP" and would
require manual seed-by-seed verification — the same coverage as the
seed-AND-filter approach above, with no extra precision.

Output: UnifiedLabelRecord-shaped JSON identical to FCA / MAS / JFSA
scrapers in this directory, so `merge_vasp_directory.py` ingests it
without code changes.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date
from pathlib import Path

# Live FINMA endpoint for the master register CSV. CDN blocks scripted
# clients with HTTP/2 400 regardless of UA / cookies, so we keep this
# only for documentation and future re-attempt; runtime path is
# Wayback (below) unless --live is passed.
FINMA_LIVE_CSV = (
    "https://www.finma.ch/de/~/media/finma/dokumente/"
    "bewilligungstraeger/csv/uid.csv?la=de"
    "&hash=B1DDDBB3A9C85E3A663D45D59AF91B95"
)

# Most recent stable Wayback capture of `uid.csv` (200 OK, 70,797 bytes).
# `id_` flag returns raw bytes without Wayback's HTML wrapper.
FINMA_WAYBACK_CSV = (
    "https://web.archive.org/web/20250625063708id_/"
    "https://www.finma.ch/de/~/media/finma/dokumente/"
    "bewilligungstraeger/csv/uid.csv"
    "?hash=B1DDDBB3A9C85E3A663D45D59AF91B95&la=de"
)

# Authorisation types (English column) that are crypto-relevant.
# FinTech licence (Art 1b) entire population is in scope. Trading
# venues entire population is in scope (DLT trading systems live
# here). Banks / Securities firms / Custodian banks / Fund management
# / Portfolio managers require seed-list AND-filter.
WHITELIST_ALL = {
    "persons under Article 1b of the Banking Act",
    "Swiss trading venue",
    "Multilateral trading system",
    "Organised trading facility",
}
WHITELIST_WITH_SEED = {
    "Bank",
    "Securities firm",
    "Custodian bank",
    "Central custodian",  # SIX Digital Exchange AG (digital-asset CSD)
    "Fund management company",
    "Portfolio manager",
    "Manager of collective assets",
    "Representatives of foreign collective investment schemes (CISA)",
    "Branch of a foreign bank",
    "Branch of a foreign securities firm",
}

# Known Swiss crypto / digital-asset firms. Public knowledge from FINMA
# press releases, firms' own ICO/launch announcements, Swiss CryptoValley
# Association membership, public M&A coverage. Names are matched
# case-insensitively against the FINMA `Name` column with substring
# semantics — typos in either side fall through to skipped[].
CRYPTO_SEEDS: tuple[str, ...] = (
    "Sygnum",
    "AMINA",
    "SEBA",                # legacy name pre-AMINA rebrand
    "Bitcoin Suisse",
    "Crypto Finance",
    "Crypto Broker",
    "Crypto Storage",
    "21Shares",
    "21.co",
    "BX Swiss",
    "SDX Trading",
    "SIX Digital",
    "Bitcoin Capital",
    "CV VC",
    "Taurus",
    "Metaco",
    "Mt Pelerin",
    "Mt. Pelerin",
    "Lykke",
    "Bity",
    "Swissquote",          # Swissquote Bank is a major CH crypto-onramp
    "Bitstamp",            # has CH presence via Bitstamp Europe
    "Coinbase Custody",
    "Bitcoin Lightning",
    "Relai",
    "Nexo",
    "Tezos",
    "Cardano",
    "Ethereum Switzerland",
    "Solana Switzerland",
    "DFINITY",
    "Cardossier",
    "Swisspeers",          # blockchain-based lending platform
    "Yapeal",              # FinTech licence holder, digital banking
    "SR Saphirstein",      # FinTech licence holder
    "Relio",               # FinTech licence holder
    "Bivial",              # FinTech licence holder
    "Hyperion Fintech",
    "Proseba",             # crypto-asset portfolio manager
    "Tokenify",
    "Wisekey",
    "AlpenChain",
    "FlowBank",            # had crypto offerings (revoked 2024)
    "Dukascopy",
    "Postfinance Crypto",
    "Postfinance",         # PostFinance launched crypto trading 2024
    "InCore",              # InCore Bank — crypto custody
    "VAR Capital",
    "Hodl",
    "Coinify",
    "Bitcoin",             # broad sweep — any CH firm with "Bitcoin" in name
    "Crypto",              # broad sweep
    "Token",
    "Blockchain",
    "Ledger",
    "DLT",
    "Web3",
    "Decentralised",
    "Decentralized",
    "Nakamoto",
    "Algorand",
    "Polkadot",
    "Polygon",
    "Chainlink",
    "Stablecoin",
    "Digital Asset",
    "Digital Assets",
    "DigitalAssets",
)


@dataclass(frozen=True)
class FinmaEntity:
    """One row of `uid.csv`, parsed and typed."""

    name: str
    city: str
    auth_type_de: str
    auth_type_fr: str
    auth_type_it: str
    auth_type_en: str
    uid: str

    @property
    def slug(self) -> str:
        """Lower-kebab firm slug used as license_id when UID is empty."""
        return re.sub(r"[^a-z0-9]+", "-", self.name.lower()).strip("-")


def fetch_csv(url: str, retries: int = 3, sleep: float = 1.0) -> str:
    """HTTP GET with retry. Returns decoded UTF-8 (BOM-stripped) body."""

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; aidecisions-research/0.1; "
            "+https://aidecisions.ai/research)"
        ),
        "Accept": "text/csv,application/csv,text/plain;q=0.9,*/*;q=0.5",
        "Accept-Language": "de-CH,de;q=0.9,en;q=0.7",
    }
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read()
            time.sleep(sleep)
            text = raw.decode("utf-8-sig", errors="replace")
            if not text.strip().lower().startswith('"name"') and \
               '"Name"' not in text[:200]:
                # Wayback occasionally returns an HTML wrapper; treat
                # as transient.
                raise RuntimeError(
                    f"unexpected payload (first 200 chars): {text[:200]!r}"
                )
            return text
        except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            last_exc = exc
            if attempt == retries - 1:
                break
            time.sleep(2 ** attempt)
    assert last_exc is not None
    raise last_exc


def parse_uid_csv(text: str) -> list[FinmaEntity]:
    """Parse `uid.csv` into typed rows. Header is semicolon-delimited."""

    reader = csv.DictReader(io.StringIO(text), delimiter=";", quotechar='"')
    out: list[FinmaEntity] = []
    for row in reader:
        out.append(
            FinmaEntity(
                name=(row.get("Name") or "").strip(),
                city=(row.get("City") or "").strip(),
                auth_type_de=(row.get("AuthorisationTypeDE") or "").strip(),
                auth_type_fr=(row.get("AuthorisationTypeFR") or "").strip(),
                auth_type_it=(row.get("AuthorisationTypeIT") or "").strip(),
                auth_type_en=(row.get("AuthorisationTypeEN") or "").strip(),
                uid=(row.get("UID") or "").strip(),
            )
        )
    return out


def matches_crypto_seed(name: str) -> str | None:
    """Return matching seed (longest match wins), or None."""
    name_l = name.lower()
    best: str | None = None
    for seed in CRYPTO_SEEDS:
        if seed.lower() in name_l:
            if best is None or len(seed) > len(best):
                best = seed
    return best


def filter_vasps(
    rows: list[FinmaEntity],
) -> tuple[list[tuple[FinmaEntity, str]], list[tuple[str, str]]]:
    """Apply the VASP filter.

    Returns (kept, skipped) where:
      - kept = list of (entity, match_reason)
      - skipped = list of (entity_name, reason) — only rows that
        looked crypto-named but failed the auth-type whitelist; pure
        non-crypto rows are dropped silently to keep stdout readable.
    """

    kept: dict[tuple[str, str], tuple[FinmaEntity, str]] = {}
    skipped: list[tuple[str, str]] = []

    for ent in rows:
        seed = matches_crypto_seed(ent.name)
        # Path 1: auth type is in the unconditional whitelist
        if ent.auth_type_en in WHITELIST_ALL:
            reason = f"auth-type:{ent.auth_type_en}"
            kept[(ent.uid, ent.auth_type_en)] = (ent, reason)
            continue
        # Path 2: auth type needs seed match
        if ent.auth_type_en in WHITELIST_WITH_SEED and seed is not None:
            reason = f"seed:{seed}|auth:{ent.auth_type_en}"
            kept[(ent.uid, ent.auth_type_en)] = (ent, reason)
            continue
        # Diagnostic: name looked crypto but auth type not whitelisted
        if seed is not None and ent.auth_type_en not in WHITELIST_ALL:
            if ent.auth_type_en not in WHITELIST_WITH_SEED:
                skipped.append(
                    (
                        f"{ent.name} ({ent.city})",
                        f"auth-type not whitelisted: {ent.auth_type_en}",
                    )
                )

    return list(kept.values()), skipped


def to_unified_record(
    ent: FinmaEntity, match_reason: str, today: date, source_url: str
) -> dict:
    """Project a FINMA row into the project's UnifiedLabelRecord shape."""

    license_id = ent.uid or f"slug-{ent.slug}"
    address_id = (
        f"ch_finma::license_id::{ent.uid}"
        if ent.uid
        else f"ch_finma::name::{ent.slug}"
    )
    return {
        "address": address_id,
        "chain": "multi",
        "labels": [
            {
                "name": ent.name,
                "type": "exchange",
                "source": "ch_finma_register",
                "chain": "multi",
            }
        ],
        "is_exchange": True,
        "is_illicit": False,
        "is_ai_agent": False,
        "entity_name": ent.name,
        "category": "vasp",
        "jurisdiction": "CH",
        "license_id": license_id,
        "regulator": "Swiss Financial Market Supervisory Authority (CH FINMA)",
        "license_status": "active",
        "sanctioned": False,
        "source_url": source_url,
        "source_date": today.isoformat(),
        "_ch_uid": ent.uid or None,
        "_ch_legal_form": _legal_form_from_name(ent.name),
        "_ch_city": ent.city or None,
        "_ch_activity_class": ent.auth_type_en or None,
        "_ch_activity_class_de": ent.auth_type_de or None,
        "_ch_activity_class_fr": ent.auth_type_fr or None,
        "_ch_activity_class_it": ent.auth_type_it or None,
        "_ch_match_reason": match_reason,
    }


def _legal_form_from_name(name: str) -> str | None:
    """Heuristic legal-form extractor from CH legal-name suffixes."""
    upper = name.upper()
    for suffix in (
        " AG", " SA", " S.A.", " GMBH", " SARL", " S.A.R.L.", " AKTIENGESELLSCHAFT",
        " LIMITED", " LTD", " LTD.", " LLC", " HOLDING",
    ):
        if upper.endswith(suffix) or upper.endswith(suffix + "."):
            return suffix.strip().rstrip(".")
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / "labels_raw" /
        f"ch_finma_vasps_{date.today().isoformat()}.json",
    )
    parser.add_argument(
        "--source-url",
        type=str,
        default=FINMA_WAYBACK_CSV,
        help="Override CSV source. Default: Wayback capture 2025-06-25.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Try live finma.ch endpoint first, fall back to Wayback. "
        "(Live endpoint typically blocks scripted clients.)",
    )
    parser.add_argument("--sleep", type=float, default=0.5)
    args = parser.parse_args()

    candidates: list[str] = []
    if args.live:
        candidates.append(FINMA_LIVE_CSV)
    candidates.append(args.source_url)

    text: str | None = None
    used_url: str | None = None
    fetch_errors: list[tuple[str, str]] = []
    for url in candidates:
        try:
            print(f"Fetching FINMA register: {url[:100]} …", flush=True)
            text = fetch_csv(url, sleep=args.sleep)
            used_url = url
            break
        except Exception as exc:
            fetch_errors.append((url, repr(exc)))
            print(f"  failed: {exc}", flush=True)

    if text is None:
        print(
            "ERROR: no FINMA source reachable. Errors:",
            file=sys.stderr,
        )
        for url, err in fetch_errors:
            print(f"  {url[:100]} → {err}", file=sys.stderr)
        sys.exit(2)

    rows = parse_uid_csv(text)
    print(f"Parsed {len(rows)} rows from FINMA uid.csv "
          f"(source: {used_url[:80]} …)", flush=True)

    kept, skipped = filter_vasps(rows)
    today = date.today()
    # Citation URL on the official FINMA site (not the Wayback wrapper),
    # so DD reviewers can re-fetch if/when CDN allows.
    citation_url = (
        "https://www.finma.ch/en/finma-public/"
        "authorised-institutions-individuals-and-products/"
    )
    records = [to_unified_record(e, r, today, citation_url) for e, r in kept]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)

    print(f"\nMatched (CH FINMA crypto/VASP): {len(records)}")
    print("\nTop entries:")
    # Stable preview ordering: by name then auth_type for reproducibility.
    preview = sorted(
        records,
        key=lambda r: (r["entity_name"].lower(), r["_ch_activity_class"] or ""),
    )
    for r in preview[:15]:
        print(
            f"  {r['_ch_uid'] or '(no-uid)':22s} "
            f"{r['entity_name'][:42]:42s} "
            f"{r['_ch_activity_class'][:30] if r['_ch_activity_class'] else '-':30s} "
            f"{r['_ch_city'] or '-'}"
        )
    if skipped:
        print(f"\nSkipped (crypto-named but auth-type not whitelisted), "
              f"first 10 of {len(skipped)}:")
        for n, reason in skipped[:10]:
            print(f"  - {n[:55]:55s}  ({reason[:50]})")
    print(f"\nOutput: {args.output}")


if __name__ == "__main__":
    main()
