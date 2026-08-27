#!/usr/bin/env python3
"""UAE VARA Public Register scraper.

Source: VARA (Virtual Assets Regulatory Authority — Dubai) Public
Register at `https://www.vara.ae/en/licenses-and-register/public-register/`.

Why direct HTML parsing (not API):
The VARA site is built with Gatsby + Umbraco. The page-data.json that
Gatsby exports for the static build contains stale "Lorem Ipsum"
placeholders (varaRegistryList component, never actually populated for
the public consumer). The REAL licensee table is rendered server-side
into the response HTML as a `<table>` with `<td data-label="VASP Name">`
… `<td data-label="Reference">` cells. We parse that table.

Scope:
  - UAE VARA only (Dubai jurisdiction, code "AE-DU").
  - ADGM FSRA (Abu Dhabi Global Market — separate UAE crypto regulator)
    is OUT of scope.

VARA licence categories captured into _vara_categories:
  - Advisory Services
  - Broker-Dealer Services
  - Custody Services (incl. custodial staking)
  - Exchange Services (incl. VA Derivatives Trading)
  - Lending and Borrowing Services
  - Management and Investment Services
  - VA Issuance (Category 1)
  - Transfer and Settlement / Payment and Remittances Services

All 7+ categories are treated as VASP per FATF + DD-survivable.

Anti-padding:
If the live page returns 0 rows or the table shape changes, exit 2 with
a clear message. Never fall back to a hardcoded list.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

REGISTER_URL = "https://www.vara.ae/en/licenses-and-register/public-register/"
WAYBACK_FALLBACK_URL = (
    "https://web.archive.org/web/20260513073801/"
    "https://www.vara.ae/en/licenses-and-register/public-register/"
)

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 aidecisions-research/0.1"
)


@dataclass(frozen=True)
class VaraLicensee:
    vasp_name: str
    licence_type: str
    reference: str
    licensed_activities: list[str] = field(default_factory=list)
    licence_issued: str | None = None
    status: str = ""
    sca_registration: str | None = None


def fetch(url: str, retries: int = 3, sleep: float = 0.5,
          timeout: int = 30) -> str:
    """HTTP GET with retry + backoff."""

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            time.sleep(sleep)
            return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError(f"unreachable; last={last_exc!r}")


def parse_register_table(html: str) -> list[VaraLicensee]:
    """Extract licensee rows from the VARA Public Register HTML table.

    Each `<tr>` carries `<td data-label="…">…</td>` cells. We pick out
    rows that contain a non-empty `VASP Name` cell.
    """

    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.DOTALL)
    licensees: list[VaraLicensee] = []
    for row_html in rows:
        cells = re.findall(
            r'<td[^>]*data-label="([^"]+)"[^>]*>(.*?)</td>',
            row_html,
            re.DOTALL,
        )
        if not cells:
            continue
        record: dict[str, str] = {}
        for label, content in cells:
            text = re.sub(r"<[^>]+>", " ", content)
            text = (
                text.replace("&amp;", "&")
                    .replace("&nbsp;", " ")
                    .replace("&#39;", "'")
            )
            text = re.sub(r"\s+", " ", text).strip()
            record[label] = text
        name = record.get("VASP Name", "").strip()
        if not name:
            continue
        activities_raw = record.get("Licensed Activities", "").strip()
        activities = split_activities(activities_raw)
        licensees.append(
            VaraLicensee(
                vasp_name=name,
                licence_type=record.get("Licence Type", "").strip(),
                reference=record.get("Reference", "").strip(),
                licensed_activities=activities,
                licence_issued=record.get("Licence Issued", "").strip() or None,
                status=record.get("Status", "").strip(),
                sca_registration=record.get(
                    "SCA Registration Number", ""
                ).strip() or None,
            )
        )
    return licensees


# Canonical VARA activity vocabulary. Anchored to the labels seen in
# the VARA Activity Rulebooks (VARA Rulebook Series, 2023+).
# IMPORTANT: longest patterns first — "Category 1 VA Issuance" must
# anchor before "VA Issuance" so the regex consumes the full token
# rather than leaving "Category 1" attached to the previous activity.
VARA_ACTIVITY_TOKENS = (
    "Category 1 VA Issuance",
    "Category 2 VA Issuance",
    "VA Custody Services",
    "Advisory Services",
    "Broker-Dealer Services",
    "Custody Services",
    "Exchange Services",
    "Lending and Borrowing Services",
    "Management and Investment Services",
    "Payment and Remittances Services",
    "Transfer and Settlement Services",
    "VA Issuance",
)


def split_activities(text: str) -> list[str]:
    """The Licensed Activities cell concatenates multiple activity
    labels with no separator (each was a separate `<li>` in the source).
    Greedy-match against the canonical VARA vocabulary, attaching any
    bracketed qualifier (e.g. "[including custodial staking]") to its
    parent activity.
    """

    if not text:
        return []
    tokens: list[str] = []
    pattern = re.compile(
        "|".join(re.escape(t) for t in VARA_ACTIVITY_TOKENS)
    )
    matches = list(pattern.finditer(text))
    if not matches:
        return [text]
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        chunk = text[start:end].strip()
        if chunk:
            tokens.append(chunk)
    return tokens or [text]


def normalize_status(raw: str) -> str:
    s = (raw or "").strip().lower()
    if s in {"active", "issued"}:
        return "active"
    if s in {"revoked", "withdrawn", "cancelled", "canceled"}:
        return "revoked"
    if s in {"suspended"}:
        return "suspended"
    if s in {"pending", "in-principle approval", "ipa"}:
        return "pending"
    return "active" if "active" in s else (s or "active")


def parse_iso_date(value: str | None) -> str | None:
    if not value:
        return None
    for fmt in ("%Y/%m/%d", "%d/%m/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def slugify(name: str) -> str:
    s = name.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s[:80]


def to_unified_record(lic: VaraLicensee, today: date) -> dict:
    """Map VARA licensee → UnifiedLabelRecord shape (matches the
    VASP-directory schema, parallels FCA/MAS/NYDFS records)."""

    license_id = lic.reference or ""
    if license_id:
        address = f"uae_vara::license_id::{license_id}"
    else:
        address = f"uae_vara::name::{slugify(lic.vasp_name)}"

    # Strip the "(trade name)" parenthetical for the canonical entity_name
    # while keeping the legal form intact (FZE / FZCO / DMCC / LLC / PJSC).
    legal_name = re.sub(r"\s*\([^)]*\)\s*$", "", lic.vasp_name).strip()

    issued_iso = parse_iso_date(lic.licence_issued)
    license_status = normalize_status(lic.status)

    return {
        # No on-chain address yet — VARA reference is the canonical key.
        # The address-mapping layer maps these entities to known on-chain wallet addresses.
        "address": address,
        "chain": "multi",
        "labels": [
            {
                "name": legal_name,
                "type": "exchange",
                "source": "uae_vara_register",
                "chain": "multi",
            }
        ],
        "is_exchange": True,
        "is_illicit": False,
        "is_ai_agent": False,
        "entity_name": legal_name,
        "category": "vasp",
        # ISO-3166-2 subdivision: AE-DU (Dubai). VARA jurisdiction is
        # Dubai-only; ADGM FSRA covers Abu Dhabi separately.
        "jurisdiction": "AE-DU",
        "license_id": license_id,
        "regulator": "Virtual Asset Regulatory Authority (UAE VARA)",
        "license_status": license_status,
        "sanctioned": False,
        "source_url": REGISTER_URL,
        "source_date": today.isoformat(),
        "_vara_categories": lic.licensed_activities,
        "_vara_licence_class": lic.licence_type,
        "_vara_licence_issued": issued_iso,
        "_vara_status_raw": lic.status,
        "_vara_sca_registration": lic.sca_registration,
        "_vara_emirate": "Dubai",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data")
        / "labels_raw"
        / f"uae_vara_vasps_{date.today().isoformat()}.json",
    )
    parser.add_argument(
        "--source",
        choices=("live", "wayback", "auto"),
        default="auto",
        help=(
            "live = vara.ae direct; wayback = web.archive.org snapshot; "
            "auto = try live, fall back to wayback only if live yields 0 rows."
        ),
    )
    parser.add_argument("--sleep", type=float, default=0.5)
    args = parser.parse_args()

    today = date.today()

    def fetch_from(url: str) -> tuple[str, list[VaraLicensee]]:
        print(f"GET {url}", flush=True)
        html = fetch(url, sleep=args.sleep)
        rows = parse_register_table(html)
        print(f"  → parsed {len(rows)} rows from this source", flush=True)
        return html, rows

    licensees: list[VaraLicensee] = []
    used_url = REGISTER_URL
    if args.source in ("live", "auto"):
        try:
            _, licensees = fetch_from(REGISTER_URL)
        except Exception as exc:
            print(f"  live fetch failed: {exc!r}", flush=True)
            licensees = []
        if not licensees and args.source == "live":
            print(
                "ERROR: VARA live page returned 0 rows. Site shape may "
                "have changed. Inspect HTML manually before re-running. "
                "No fallback used (anti-padding rule).",
                file=sys.stderr,
            )
            return 2
    if not licensees and args.source in ("wayback", "auto"):
        print(
            "Falling back to Wayback Machine snapshot "
            "(2026-05-13). This is documented, not silent.",
            flush=True,
        )
        _, licensees = fetch_from(WAYBACK_FALLBACK_URL)
        used_url = WAYBACK_FALLBACK_URL

    if not licensees:
        print(
            "ERROR: 0 licensees from both live and wayback. "
            "Source structurally changed. Exit 2.",
            file=sys.stderr,
        )
        return 2

    records = [to_unified_record(lic, today) for lic in licensees]
    # When the wayback snapshot is the source, mark source_url
    # explicitly so the audit trail is honest.
    if used_url != REGISTER_URL:
        for r in records:
            r["source_url"] = used_url
            r["_vara_source_note"] = "wayback-snapshot-2026-05-13"

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)

    print()
    print(f"Total licensees: {len(licensees)}")
    print(f"Source: {used_url}")
    print()
    print("By primary activity:")
    by_cat: dict[str, int] = {}
    for lic in licensees:
        for act in lic.licensed_activities or ["(none)"]:
            head = act.split("[")[0].split("(")[0].strip()
            by_cat[head] = by_cat.get(head, 0) + 1
    for k in sorted(by_cat, key=lambda x: -by_cat[x]):
        print(f"  {by_cat[k]:3d}  {k}")

    print()
    print("First 10 licensees:")
    for lic in licensees[:10]:
        cats = ", ".join(
            a.split("[")[0].split("(")[0].strip()
            for a in lic.licensed_activities
        ) or "(none)"
        print(
            f"  {lic.reference:18s} {lic.vasp_name[:40]:40s} "
            f"{lic.status[:10]:10s} cats=[{cats}]"
        )

    print()
    print(f"Output: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
