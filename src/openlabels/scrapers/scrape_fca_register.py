#!/usr/bin/env python3
"""UK FCA Financial Services Register scraper.

Source: register.fca.org.uk Public REST API. Requires registration at
register.fca.org.uk/Developer/ → email + API key. Headers:
`X-Auth-Email` + `X-Auth-Key`.

Why a seed-list approach (not bulk-dump):
The FCA register API is search-only. There is no `/Firm?cryptoasset=true`
filter and no published bulk CSV of MLR-registered cryptoasset firms.
The salesforce front-end at register.fca.org.uk/s/search?predefined=CA
renders the cryptoasset list via Lightning/Aura on the client; the
api/v0.1 endpoint rejects `predefined=CA`.

Practical path: keep a curated seed list of known UK cryptoasset firms
(public knowledge from FCA press releases, CryptoUK industry register,
firms' own MLR-registration announcements). For each name:
  1. Search firm by name           → list of candidate FRNs
  2. Per FRN: GET /Firm/{FRN}      → full record with MLRs Status field
  3. Keep only `MLRs Status == "MLRs Registered"` records

This produces a citable, DD-survivable per-firm record (FRN, MLRs
Effective Date, Organisation Name, Status) — exactly what an exchange
sandbox needs to confirm UK FCA registration status.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

API_BASE = "https://register.fca.org.uk/services/V0.1"


# Seed list of known UK MLR-registered cryptoasset firms.
# Sources: public FCA press releases 2020-2026, CryptoUK industry list,
# firms' own MLR-registration press releases. Any name we miss can be
# added to this list — verifier still calls FCA per-FRN to confirm
# MLR status, so a wrong name only adds an entry to skipped[].
SEED_FIRMS: list[str] = [
    # Tier 1: top UK exchanges + payment firms
    "Crypto Facilities",          # Kraken UK arm
    "CB Payments Ltd",            # Coinbase UK
    "Gemini Europe Services",
    "Bitstamp Limited",
    "eToro (UK)",
    "Revolut",
    "Archax",
    "Globalblock",
    "Wintermute Trading",
    "B2C2",
    "Galaxy Digital UK",
    "Solarisbank UK",
    "Komainu (UK)",
    "Trustology (Bitpanda Custody)",
    "Copper Technologies",
    "Zodia Custody",
    "Fidelity Digital Assets Services",
    # Mid-tier UK-registered cryptoasset firms
    "Skrill",
    "Paysafe Payment Solutions",
    "Bitfinex Securities",
    "BCB Payments",
    "Onyx Markets",
    "Centaur Investment",
    "DigitalAssetsAB",
    "DCG Group",
    "Bitpanda Limited",
    "Crypto.com UK",
    "Mode Global Holdings",
    "Ziglu",
    "Plutus DAO",
    "Aquanow",
    "Solidi",
    "Ramp Network",
    "Moonpay UK",
    "MoonPay Technology Services",
    "Transak Tech",
    "Kraken Payward UK",
    "Hidden Road Partners",
    "Standard Chartered Crypto",
    "Sygnum Bank",
    "Komainu",
    # Travel-rule + custody specialists
    "Notabene UK",
    "Sumsub",
    "Onfido",
    "Chainalysis UK",
    "Fireblocks UK",
    "TRM Labs UK",
    "Elliptic Enterprises",
    # Specialist cryptoasset firms
    "BitMex UK",
    "Genesis Trading UK",
    "Cumberland UK",
    "Flow Traders UK",
    "Jane Street UK",
]


@dataclass(frozen=True)
class FcaFirm:
    frn: str
    organisation_name: str
    status: str
    mlr_status: str | None
    mlr_effective_date: str | None
    business_type: str | None
    companies_house_number: str | None


class FcaClient:
    """Thin REST wrapper with retry + per-call headers."""

    def __init__(self, email: str, api_key: str, sleep: float = 0.2):
        self._email = email
        self._key = api_key
        self._sleep = sleep

    def _request(self, path: str, retries: int = 3) -> dict:
        url = f"{API_BASE}{path}"
        headers = {
            "X-Auth-Email": self._email,
            "X-Auth-Key": self._key,
            "Accept": "application/json",
            "User-Agent": "aidecisions-research/0.1",
        }
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=20) as resp:
                    return json.load(resp)
            except (urllib.error.URLError, TimeoutError):
                if attempt == retries - 1:
                    raise
                time.sleep(2 ** attempt)
        raise RuntimeError("unreachable")

    def search_firm(self, query: str) -> list[dict]:
        path = f"/Search?{urllib.parse.urlencode({'q': query, 'type': 'firm'})}"
        payload = self._request(path)
        time.sleep(self._sleep)
        return payload.get("Data") or []

    def get_firm(self, frn: str) -> dict | None:
        try:
            payload = self._request(f"/Firm/{frn}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        time.sleep(self._sleep)
        data = payload.get("Data") or []
        return data[0] if data else None


def to_fca_firm(record: dict) -> FcaFirm:
    return FcaFirm(
        frn=record.get("FRN", ""),
        organisation_name=record.get("Organisation Name", ""),
        status=record.get("Status", ""),
        mlr_status=record.get("MLRs Status") or None,
        mlr_effective_date=record.get("MLRs Status Effective Date") or None,
        business_type=record.get("Business Type") or None,
        companies_house_number=record.get("Companies House Number") or None,
    )


def parse_uk_date(value: str | None) -> str | None:
    if not value:
        return None
    for fmt in ("%d/%m/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def to_unified_record(firm: FcaFirm, today: date) -> dict:
    iso_eff = parse_uk_date(firm.mlr_effective_date)
    license_status = "active"
    if firm.status.lower() in {"no longer authorised", "deauthorised"}:
        license_status = "revoked"
    elif firm.status.lower() in {"applied", "in progress"}:
        license_status = "pending"

    return {
        # No on-chain address yet — use FRN-derived ID. The address-mapping layer maps these
        # entities to known on-chain wallet addresses.
        "address": f"fca::frn::{firm.frn}",
        "chain": "multi",
        "labels": [
            {
                "name": firm.organisation_name,
                "type": "exchange",
                "source": "fca_register_uk",
                "chain": "multi",
            }
        ],
        "is_exchange": True,
        "is_illicit": False,
        "is_ai_agent": False,
        "entity_name": firm.organisation_name,
        "category": "vasp",
        "jurisdiction": "GB",
        "license_id": firm.frn,
        "regulator": "Financial Conduct Authority (FCA)",
        "license_status": license_status,
        "sanctioned": False,
        "source_url": f"https://register.fca.org.uk/s/firm?id={firm.frn}",
        "source_date": today.isoformat(),
        "_fca_frn": firm.frn,
        "_fca_status": firm.status,
        "_fca_mlr_status": firm.mlr_status,
        "_fca_mlr_effective_date": iso_eff,
        "_fca_business_type": firm.business_type,
        "_fca_companies_house": firm.companies_house_number,
    }


def collect(
    client: FcaClient, seeds: list[str]
) -> tuple[list[FcaFirm], list[tuple[str, str]]]:
    """Resolve each seed name to FRN(s) → fetch full record → keep only
    MLR-registered firms.

    Returns (matched, skipped) where skipped is a list of
    (seed_name, reason) tuples for diagnostic output.
    """
    matched: dict[str, FcaFirm] = {}
    skipped: list[tuple[str, str]] = []

    for seed in seeds:
        results = client.search_firm(seed)
        if not results:
            skipped.append((seed, "no search hits"))
            continue
        candidate_frns: list[str] = []
        for r in results:
            url = r.get("URL") or ""
            if "/Firm/" in url:
                frn = url.rsplit("/Firm/", 1)[1]
                candidate_frns.append(frn)
            elif r.get("Type of business or Individual") == "Firm":
                # Some search hits carry the FRN in "Reference Number"
                # without a usable URL — fall back to that.
                ref = r.get("Reference Number")
                if ref:
                    candidate_frns.append(str(ref))
        if not candidate_frns:
            skipped.append((seed, "no firm-typed hits"))
            continue
        kept = 0
        for frn in candidate_frns[:5]:  # cap candidates per seed
            if frn in matched:
                continue
            record = client.get_firm(frn)
            if not record:
                continue
            firm = to_fca_firm(record)
            if firm.mlr_status == "MLRs Registered":
                matched[frn] = firm
                kept += 1
        if kept == 0:
            skipped.append((seed, "no MLR-registered candidate FRN"))

    return list(matched.values()), skipped


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / "labels_raw" /
        f"fca_register_vasps_{date.today().isoformat()}.json",
    )
    parser.add_argument("--sleep", type=float, default=0.25)
    args = parser.parse_args()

    email = os.environ.get("FCA_API_EMAIL")
    api_key = os.environ.get("FCA_API_KEY")
    if not email or not api_key:
        print("ERROR: FCA_API_EMAIL + FCA_API_KEY environment variables required. "
              "Register at https://register.fca.org.uk/Developer/",
              file=sys.stderr)
        sys.exit(2)

    today = date.today()
    client = FcaClient(email=email, api_key=api_key, sleep=args.sleep)

    print(f"Seeding {len(SEED_FIRMS)} firm-name queries via FCA Search …",
          flush=True)
    matched, skipped = collect(client, SEED_FIRMS)
    records = [to_unified_record(f, today) for f in matched]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)

    print(f"\nMatched (MLR-registered): {len(matched)}")
    print(f"Skipped seeds: {len(skipped)}")
    print("\nMatched firms:")
    for f in matched:
        print(f"  FRN {f.frn}  {f.organisation_name[:60]:60s} "
              f"MLR eff {f.mlr_effective_date}")
    if skipped:
        print(f"\nSkipped (first 20 of {len(skipped)}):")
        for seed, reason in skipped[:20]:
            print(f"  - {seed[:50]:50s}  ({reason})")
    print(f"\nOutput: {args.output}")


if __name__ == "__main__":
    main()
