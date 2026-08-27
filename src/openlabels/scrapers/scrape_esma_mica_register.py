#!/usr/bin/env python3
"""ESMA MiCA register scraper.

Source: ESMA publishes consolidated MiCA register CSVs at
`https://www.esma.europa.eu/sites/default/files/2024-12/<NAME>.csv`. A
single download per file replaces what would otherwise be 27 national
scrapers (one per EU member state). The `ae_competentAuthority` column
records which national regulator granted the authorisation.

Files:
  - CASPS.csv  authorised crypto-asset service providers (Article 62)
  - NCASP.csv  notification-only / pre-existing CASPs under transitional
               regime (Article 143). These are firms providing
               crypto-asset services that existed before MiCA and
               notified national authorities under the transitional
               regime; they are recorded in the register even before
               authorisation under the new regime.

ARTZZ.csv (asset-referenced tokens) and EMTWP.csv (e-money tokens) are
*token issuance* registers, not VASP service-provider registers — they
are out of scope here.

Output is one UnifiedLabelRecord-shaped JSON file per source. The
records carry `chain="multi"` because MiCA authorisation is chain-
agnostic; address-level chain mapping happens downstream when we map each
entity to known on-chain addresses (Binance EU CASP → Binance hot/cold
wallet addresses across ETH / Tron / BSC).
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

ESMA_BASE = "https://www.esma.europa.eu/sites/default/files/2024-12"
SOURCES = {
    "casps": "CASPS.csv",
    "ncasp": "NCASP.csv",
}


@dataclass(frozen=True)
class EsmaRow:
    """One row from CASPS.csv or NCASP.csv after parsing."""

    competent_authority: str
    home_member_state: str
    lei_name: str
    lei: str
    lei_cou_code: str
    commercial_name: str
    address: str | None
    website: str | None
    authorisation_date: str | None
    authorisation_end_date: str | None
    service_codes: str | None
    passporting_countries: str | None
    last_update: str | None
    source_file: str
    raw: dict[str, str]


def fetch_csv(filename: str, retries: int = 3) -> str:
    """Fetch one ESMA CSV, retry with exponential backoff."""

    url = f"{ESMA_BASE}/{filename}"
    headers = {"User-Agent": "aidecisions-research/0.1", "Accept": "text/csv"}

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
            return raw.decode("utf-8-sig", errors="replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == retries - 1:
                raise
            wait = 2 ** attempt
            print(f"  [{filename}] retry {attempt+1}/{retries} after {wait}s ({exc})", file=sys.stderr)
            time.sleep(wait)
    raise RuntimeError("unreachable")


def _sanitise(value: str) -> str:
    """Strip ESMA-source U+FFFD replacement chars introduced during CSV
    export. ESMA's CSVs ship with `\\xef\\xbf\\xbd` in place of certain
    non-ASCII characters (Donau-City-Straße, Stella-Klein-Löw-Weg,
    "Kraken" smart-quotes). The original character is unrecoverable
    without a parallel data source, so we replace with empty / single
    space to keep entity-name lookups predictable downstream.
    """
    return value.replace("�", "").strip()


def parse_rows(content: str, source_file: str) -> list[EsmaRow]:
    rows: list[EsmaRow] = []
    reader = csv.DictReader(io.StringIO(content))
    for raw in reader:
        cleaned = {
            k.strip(): (_sanitise(v) if isinstance(v, str) else v)
            for k, v in raw.items()
            if k
        }
        commercial = cleaned.get("ae_commercial_name") or cleaned.get("ae_lei_name") or ""
        if not commercial:
            continue
        rows.append(
            EsmaRow(
                competent_authority=cleaned.get("ae_competentAuthority", ""),
                home_member_state=cleaned.get("ae_homeMemberState", ""),
                lei_name=cleaned.get("ae_lei_name", ""),
                lei=cleaned.get("ae_lei", ""),
                lei_cou_code=cleaned.get("ae_lei_cou_code", ""),
                commercial_name=commercial,
                address=cleaned.get("ae_address") or None,
                website=cleaned.get("ae_website") or None,
                authorisation_date=cleaned.get("ac_authorisationNotificationDate")
                or cleaned.get("ae_decision_date") or None,
                authorisation_end_date=cleaned.get("ac_authorisationEndDate") or None,
                service_codes=cleaned.get("ac_serviceCode") or None,
                passporting_countries=cleaned.get("ac_serviceCode_cou") or None,
                last_update=cleaned.get("ac_lastupdate") or cleaned.get("ae_lastupdate") or None,
                source_file=source_file,
                raw=cleaned,
            )
        )
    return rows


def parse_eu_date(value: str | None) -> str | None:
    """Convert dd/mm/yyyy or yyyy-mm-dd to ISO yyyy-mm-dd, else None."""

    if not value:
        return None
    for fmt in ("%d/%m/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def license_status_from_dates(authorisation: str | None, end: str | None) -> str:
    """Map ESMA authorisation dates to active / revoked / pending."""

    if end:
        return "revoked"
    if authorisation:
        return "active"
    return "pending"


def to_unified_record(row: EsmaRow, source_url: str, today: date) -> dict:
    """One ESMA row → UnifiedLabelRecord-shaped dict (v2.1)."""

    iso_auth = parse_eu_date(row.authorisation_date)
    iso_end = parse_eu_date(row.authorisation_end_date)

    return {
        # ESMA records do NOT carry on-chain addresses. The `address`
        # field here is the legal-entity LEI (Legal Entity Identifier),
        # not a wallet address. The address-mapping layer maps these LEI / commercial_name
        # entries to known on-chain addresses (e.g. Binance EU LEI →
        # Binance hot wallet 0x… on ETH).
        "address": row.lei or f"esma::{row.commercial_name.lower().replace(' ', '_')}",
        "chain": "multi",
        "labels": [
            {
                "name": row.commercial_name,
                "type": "exchange",
                "source": f"esma_mica_{row.source_file}",
                "chain": "multi",
            }
        ],
        "is_exchange": True,
        "is_illicit": False,
        "is_ai_agent": False,
        "entity_name": row.commercial_name,
        "category": "vasp",
        # Use member state ISO (2 chars) for jurisdiction; EU is implicit
        # from the register itself.
        "jurisdiction": row.home_member_state or row.lei_cou_code or None,
        "license_id": row.lei or None,
        "regulator": row.competent_authority or "ESMA (EU MiCA)",
        "license_status": license_status_from_dates(iso_auth, iso_end),
        "sanctioned": False,
        "source_url": source_url,
        "source_date": today.isoformat(),
        # ESMA-specific extras preserved on the record (extra="allow"):
        "_esma_lei": row.lei,
        "_esma_lei_legal_name": row.lei_name,
        "_esma_competent_authority": row.competent_authority,
        "_esma_home_member_state": row.home_member_state,
        "_esma_authorisation_date": iso_auth,
        "_esma_authorisation_end_date": iso_end,
        "_esma_service_codes": row.service_codes,
        "_esma_passporting_countries": row.passporting_countries,
        "_esma_website": row.website,
        "_esma_address": row.address,
        "_esma_source_file": row.source_file,
        "_esma_last_update": row.last_update,
    }


def jurisdictions_summary(records: Iterable[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in records:
        j = r.get("jurisdiction") or "??"
        out[j] = out.get(j, 0) + 1
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / "labels_raw" /
        f"esma_mica_vasps_{date.today().isoformat()}.json",
    )
    parser.add_argument("--source-url-base", default=ESMA_BASE)
    args = parser.parse_args()

    today = date.today()
    all_records: list[dict] = []
    per_source_counts: dict[str, int] = {}

    for source_key, filename in SOURCES.items():
        print(f"[{source_key}] fetching {filename} …", flush=True)
        content = fetch_csv(filename)
        rows = parse_rows(content, source_key)
        source_url = f"{args.source_url_base}/{filename}"
        records = [to_unified_record(r, source_url, today) for r in rows]
        all_records.extend(records)
        per_source_counts[source_key] = len(records)
        print(f"[{source_key}] {len(records)} records", flush=True)

    # Dedupe by LEI when present; entries without LEI dedupe by
    # (commercial_name, jurisdiction).
    by_key: dict[tuple[str, str], dict] = {}
    for rec in all_records:
        lei = rec.get("_esma_lei") or ""
        key = (lei, rec.get("jurisdiction") or "??") if lei else (
            rec["entity_name"].lower(), rec.get("jurisdiction") or "??"
        )
        if key not in by_key:
            by_key[key] = rec
        else:
            existing = by_key[key]
            for label in rec["labels"]:
                if label not in existing["labels"]:
                    existing["labels"].append(label)
    out_records = list(by_key.values())

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(out_records, fh, indent=2, ensure_ascii=False)

    print("\nPer source:")
    for k, n in per_source_counts.items():
        print(f"  {k:8s}  {n}")
    print(f"After dedupe by LEI: {len(out_records)} records")

    by_juris = jurisdictions_summary(out_records)
    print(f"\nTop jurisdictions ({len(by_juris)} distinct):")
    for j, n in sorted(by_juris.items(), key=lambda x: -x[1])[:15]:
        print(f"  {j}  {n}")

    with_lei = sum(1 for r in out_records if r.get("_esma_lei"))
    active = sum(1 for r in out_records if r["license_status"] == "active")
    print(f"\nWith LEI: {with_lei} / {len(out_records)}")
    print(f"Active license: {active} / {len(out_records)}")
    print(f"\nOutput: {args.output}")


if __name__ == "__main__":
    main()
