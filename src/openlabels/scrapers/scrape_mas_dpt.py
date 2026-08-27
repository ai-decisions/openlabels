#!/usr/bin/env python3
"""Singapore MAS DPT licensee scraper.

Source: MAS Financial Institutions Directory (FID) at
`eservices.mas.gov.sg/fid/`. The FID exposes payment institutions by
category (Major Payment Institution / Standard Payment Institution),
but it does NOT publish a consolidated "Digital Payment Token (DPT)
licensee" view. DPT activity is a per-institution flag inside
the institution-detail page, not a category filter.

Workflow:
  1. Enumerate all pages under category=Major Payment Institution
     (~25 pages × 10 records) and category=Standard Payment Institution.
  2. For each institution: GET /fid/institution/detail/{slug}
  3. Parse activity list. Keep only those carrying
     "Digital Payment Token Service" (the regulatory term used by MAS
     to label DPT-licensed firms under the Payment Services Act).
  4. Output as UnifiedLabelRecord-shaped JSON.

This produces a citable per-institution record (institution slug, MAS
URL, activity list, address, phone, website) — DD-survivable for
DPT-licensed status under SG MAS regime.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date
from pathlib import Path

FID_BASE = "https://eservices.mas.gov.sg/fid"
DPT_KEYWORDS = ("digital payment token",)


@dataclass(frozen=True)
class MasInstitution:
    slug: str
    name: str
    category: str
    detail_url: str
    activities: list[str]
    address: str | None
    website: str | None
    phone: str | None


def fetch(url: str, retries: int = 3, sleep: float = 0.4) -> str:
    """HTTP GET with retry + backoff."""

    headers = {"User-Agent": "aidecisions-research/0.1", "Accept": "text/html"}
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
            time.sleep(sleep)
            return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("unreachable")


def name_from_slug(slug: str) -> str:
    """Convert FID slug ('431405-2C2P-Pte-Ltd') to display name ('2C2P Pte Ltd').

    The slug carries the institution name with `-` as the separator.
    The leading numeric ID has no semantic meaning to consumers; drop it.
    """
    parts = slug.split("-", 1)
    if len(parts) == 1:
        return slug
    leading, rest = parts
    if leading.isdigit():
        return rest.replace("-", " ")
    return slug.replace("-", " ")


def list_institutions(category: str, max_pages: int = 50) -> list[tuple[str, str]]:
    """Yield (detail_path, name) tuples for all pages of a category.

    The MAS FID listing renders institution names elsewhere on the page
    (within an h4/h5 that we cannot reliably anchor across categories);
    we derive the display name from the slug instead, and keep the page
    listing as the authoritative URL source.
    """

    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for page in range(1, max_pages + 1):
        params = {"category": category, "page": page}
        url = f"{FID_BASE}/institution?{urllib.parse.urlencode(params)}"
        html = fetch(url)
        paths = re.findall(r'href="(/fid/institution/detail/[^"]+)"', html)
        new_paths = [p for p in paths if p not in seen]
        if not new_paths:
            break  # ran past last page
        for path in new_paths:
            seen.add(path)
            slug = path.rsplit("/", 1)[1]
            out.append((path, name_from_slug(slug)))
    return out


def extract_activities_section(html: str) -> str:
    """Locate the institution-detail content block after the category
    heading. The MPI / SPI heading is followed by a description, then
    the regulated-activity list."""
    for cat in ("Major Payment Institution", "Standard Payment Institution"):
        idx = html.find(cat)
        if idx >= 0:
            return html[idx:idx + 5000]
    return html[:8000]


def parse_detail(html: str, slug: str, name: str) -> MasInstitution:
    section = extract_activities_section(html)
    text = re.sub(r"<[^>]+>", " ", section)
    text = re.sub(r"\s+", " ", text).strip()

    # Activity tokens — MAS uses canonical activity names:
    #   Account Issuance Service / Domestic Money Transfer Service /
    #   Cross-border Money Transfer Service / Merchant Acquisition
    #   Service / E-money Issuance Service / Digital Payment Token
    #   Service / Money-changing Service.
    activities = []
    candidates = [
        "Account Issuance Service",
        "Domestic Money Transfer Service",
        "Cross-border Money Transfer Service",
        "Merchant Acquisition Service",
        "E-money Issuance Service",
        "Digital Payment Token Service",
        "Money-changing Service",
    ]
    for c in candidates:
        if c.lower() in text.lower():
            activities.append(c)

    # Category label
    category = "Major Payment Institution" if "Major Payment" in section else (
        "Standard Payment Institution" if "Standard Payment" in section else "unknown"
    )

    # Website / phone / address — best-effort regex extraction
    addr_match = re.search(
        r'<td[^>]*>\s*([0-9][^<]{15,180}\b(?:SINGAPORE|Singapore)\b[^<]*)</td>',
        html,
    )
    address = addr_match.group(1).strip() if addr_match else None

    site_match = re.search(r'href="(https?://[^"]+)"[^>]*>\s*https?://', html)
    website = site_match.group(1) if site_match else None

    phone_match = re.search(r'href="tel:([^"]+)"', html)
    phone = phone_match.group(1).strip() if phone_match else None

    return MasInstitution(
        slug=slug,
        name=name,
        category=category,
        detail_url=f"{FID_BASE}/institution/detail/{slug}",
        activities=activities,
        address=address,
        website=website,
        phone=phone,
    )


def is_dpt_licensee(inst: MasInstitution) -> bool:
    return "Digital Payment Token Service" in inst.activities


def to_unified_record(inst: MasInstitution, today: date) -> dict:
    return {
        "address": f"mas::{inst.slug}",
        "chain": "multi",
        "labels": [
            {
                "name": inst.name,
                "type": "exchange",
                "source": "mas_fid_sg",
                "chain": "multi",
            }
        ],
        "is_exchange": True,
        "is_illicit": False,
        "is_ai_agent": False,
        "entity_name": inst.name,
        "category": "vasp",
        "jurisdiction": "SG",
        "license_id": inst.slug,
        "regulator": "Monetary Authority of Singapore (MAS)",
        "license_status": "active",
        "sanctioned": False,
        "source_url": inst.detail_url,
        "source_date": today.isoformat(),
        "_mas_category": inst.category,
        "_mas_activities": inst.activities,
        "_mas_address": inst.address,
        "_mas_website": inst.website,
        "_mas_phone": inst.phone,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / "labels_raw" /
        f"mas_dpt_vasps_{date.today().isoformat()}.json",
    )
    parser.add_argument("--max-pages", type=int, default=50)
    parser.add_argument("--sleep", type=float, default=0.3)
    parser.add_argument(
        "--include-non-dpt",
        action="store_true",
        help="Keep non-DPT MPI/SPI institutions in the output (diagnostic)",
    )
    args = parser.parse_args()

    today = date.today()

    institutions: list[tuple[str, str, str]] = []  # (slug, name, category)
    for category in ("Major Payment Institution", "Standard Payment Institution"):
        print(f"[{category}] enumerating pages …", flush=True)
        listed = list_institutions(category, max_pages=args.max_pages)
        for path, name in listed:
            slug = path.rsplit("/", 1)[1]
            institutions.append((slug, name, category))
        print(f"[{category}] {len(listed)} institutions", flush=True)

    print(f"\nTotal MPI + SPI institutions: {len(institutions)}", flush=True)
    print("Fetching detail pages …", flush=True)

    parsed: list[MasInstitution] = []
    for i, (slug, name, _cat) in enumerate(institutions, 1):
        url = f"{FID_BASE}/institution/detail/{slug}"
        try:
            html = fetch(url, sleep=args.sleep)
        except urllib.error.HTTPError as exc:
            print(f"  [{i}/{len(institutions)}] {slug} HTTP {exc.code}", flush=True)
            continue
        inst = parse_detail(html, slug, name)
        parsed.append(inst)
        if i % 25 == 0:
            print(f"  [{i}/{len(institutions)}] processed", flush=True)

    dpt = [i for i in parsed if is_dpt_licensee(i)]
    print(f"\nTotal parsed: {len(parsed)}")
    print(f"DPT licensees: {len(dpt)}")

    keep = parsed if args.include_non_dpt else dpt
    records = [to_unified_record(inst, today) for inst in keep]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)

    print("\nDPT licensees:")
    for inst in dpt:
        print(f"  {inst.name[:60]:60s} ({inst.category[:25]})")
    print(f"\nOutput: {args.output}")


if __name__ == "__main__":
    main()
