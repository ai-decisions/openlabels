#!/usr/bin/env python3
"""Japan FSA Crypto-Asset Exchange Service Provider register scraper


Source: official FSA register PDF
`https://www.fsa.go.jp/menkyo/menkyoj/kasoutuka.pdf`
(暗号資産交換業者登録一覧). The FSA publishes the register exclusively
as a Japanese-language PDF, updated approximately monthly. There is no
JSON / CSV / HTML equivalent; the JVCEA (self-regulatory body) member
list is a derivative of this register, not an independent source.

PDF structure (verified 2026-05-15, rev 令和8年4月1日, 86952 bytes):
  - Header line `【全業者数：27】` declares total firm count
  - Two regional bureau sections:
      関東財務局 (Kanto Local Finance Bureau)   — 25 firms
      近畿財務局 (Kinki Local Finance Bureau)   — 2 firms
  - Per-firm columns:
      所管 / 登録番号 / 登録年月日 / 暗号資産交換業者名 / 法人番号 /
      郵便番号 / 本店等所在地 / 代表電話番号 / 取り扱う暗号資産
    → bureau / license-id / registration-date / firm-name /
       corporate-number / postal-code / head-office-address / phone /
       supported assets
  - Bureau column 所管 only carries a value on the first row of each
    bureau group; subsequent rows in the group inherit it. We track
    the most-recent non-empty 所管 row.
  - Wareki (Japanese era) dates: 平成29年9月29日 = Heisei 29 = 2017-09-29,
    令和元年9月6日 = Reiwa 1 = 2019-09-06, etc.

Output: UnifiedLabelRecord-shaped JSON identical in shape to the FCA /
MAS / NY DFS scrapers in this directory, so `merge_vasp_directory.py`
ingests it without code changes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date
from pathlib import Path

try:
    import pdfplumber
except ImportError:  # pragma: no cover
    pdfplumber = None  # checked in main(): install the `jfsa` extra


FSA_PDF_URL = "https://www.fsa.go.jp/menkyo/menkyoj/kasoutuka.pdf"
FSA_REGISTER_LANDING = "https://www.fsa.go.jp/menkyo/menkyoj/kasoutuka.pdf"

# Wareki era → first Gregorian year. Used to convert the FSA-style
# 平成29年9月29日 / 令和元年9月6日 strings to ISO-8601.
WAREKI_ERAS: dict[str, int] = {
    "令和": 2019,  # Reiwa 1 = 2019
    "平成": 1989,  # Heisei 1 = 1989
    "昭和": 1926,  # Shouwa 1 = 1926
    "大正": 1912,  # Taisho 1 = 1912
}

# Bureau name → ASCII slug + English label (kept as diagnostic; primary
# jurisdiction is JP). ASCII slug used in the canonical address ID so
# downstream consumers (URLs, SQL, alias-matchers) don't need to handle
# kanji in identifiers. JFSA delegates registration to ten Local Finance
# Bureaus; current register only uses Kanto + Kinki.
BUREAU_LABELS: dict[str, tuple[str, str]] = {
    "関東財務局": ("kanto", "Kanto Local Finance Bureau"),
    "近畿財務局": ("kinki", "Kinki Local Finance Bureau"),
    "東海財務局": ("tokai", "Tokai Local Finance Bureau"),
    "九州財務局": ("kyushu", "Kyushu Local Finance Bureau"),
    "北海道財務局": ("hokkaido", "Hokkaido Local Finance Bureau"),
    "東北財務局": ("tohoku", "Tohoku Local Finance Bureau"),
    "中国財務局": ("chugoku", "Chugoku Local Finance Bureau"),
    "四国財務局": ("shikoku", "Shikoku Local Finance Bureau"),
    "北陸財務局": ("hokuriku", "Hokuriku Local Finance Bureau"),
    "沖縄総合事務局": ("okinawa", "Okinawa General Bureau"),
}


@dataclass(frozen=True)
class JfsaFirm:
    license_number: str  # numeric portion, zero-padded (e.g. "00001")
    license_full: str    # full kanji form (e.g. "関東財務局長 第00001号")
    bureau_kanji: str    # e.g. "関東財務局"
    bureau_slug: str     # ASCII slug for canonical IDs (e.g. "kanto")
    bureau_en: str       # e.g. "Kanto Local Finance Bureau"
    name_kanji: str      # canonical legal name in Japanese (DD-survivable)
    latin_alias: str | None  # embedded Latin brand name (None when pure JP)
    corporate_number: str | None  # 法人番号 — 13-digit Japanese national corp id
    postal_code: str | None
    address_kanji: str | None
    phone: str | None
    registration_date_iso: str | None  # ISO-8601 date
    registration_date_wareki: str       # original wareki form
    supported_assets_kanji: str | None  # 取り扱う暗号資産 column raw text


def fetch_pdf(url: str, dest: Path, retries: int = 3, sleep: float = 0.5) -> Path:
    """Download FSA register PDF with retry + backoff."""

    headers = {
        "User-Agent": "aidecisions-research/0.1",
        "Accept": "application/pdf",
    }
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
            dest.write_bytes(raw)
            time.sleep(sleep)
            return dest
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("unreachable")


def parse_wareki_date(text: str) -> tuple[str | None, str]:
    """Convert e.g. '平成29年9月29日' / '令和元年9月6日' / '令和2年3月30日'
    to ISO-8601 ('2017-09-29' / '2019-09-06' / '2020-03-30').

    Returns (iso_date_or_none, original_wareki_string).
    """

    raw = (text or "").strip()
    if not raw:
        return None, ""

    # Pattern: <era><year>年<month>月<day>日, year may be '元' (= 1)
    pattern = re.compile(
        r"(令和|平成|昭和|大正)\s*(元|[０-９0-9]+)\s*年\s*([０-９0-9]+)\s*月\s*([０-９0-9]+)\s*日"
    )
    m = pattern.search(raw)
    if not m:
        return None, raw

    era, era_year_jp, month_jp, day_jp = m.groups()
    if era_year_jp == "元":
        era_year = 1
    else:
        era_year = int(_zen_to_han(era_year_jp))
    month = int(_zen_to_han(month_jp))
    day = int(_zen_to_han(day_jp))

    base = WAREKI_ERAS.get(era)
    if base is None:
        return None, raw

    gregorian = base + era_year - 1
    try:
        iso = date(gregorian, month, day).isoformat()
    except ValueError:
        return None, raw
    return iso, raw


def _zen_to_han(text: str) -> str:
    """Full-width digits → ASCII digits."""

    out = []
    for ch in text:
        code = ord(ch)
        if 0xFF10 <= code <= 0xFF19:  # ０-９
            out.append(chr(code - 0xFF10 + ord("0")))
        else:
            out.append(ch)
    return "".join(out)


def parse_license_number(text: str) -> tuple[str, str, str]:
    """Extract numeric part + bureau from a JFSA license string.

    Input examples:
      '関東財務局長\n第00001号'
      '近畿財務局長 第00001号'
      '関 東 財 務 局 長\n第00031号'   (sometimes spaced from PDF layout)

    Returns (license_number, license_full, bureau_kanji). The bureau
    is recovered from the `XX財務局長` prefix that always precedes
    `第NNNNN号`; this is a more reliable signal than the 所管 column
    (which is None on every Kanto-bureau row because pdfplumber merges
    the bureau header into the page text rather than a table cell).
    """

    raw = (text or "").strip()
    flat = re.sub(r"\s+", "", raw)  # remove all whitespace incl newlines
    m = re.search(r"第([０-９0-9]+)号", flat)
    if not m:
        return "", raw, ""
    number = _zen_to_han(m.group(1)).zfill(5)
    # Recover bureau prefix (e.g. '関東財務局長' → '関東財務局')
    bureau_match = re.match(r"([一-鿿]+?財務局)長", flat)
    bureau_kanji = bureau_match.group(1) if bureau_match else ""
    bureau_part = f"{bureau_kanji}長" if bureau_kanji else ""
    full = f"{bureau_part} 第{number}号" if bureau_part else f"第{number}号"
    return number, full, bureau_kanji


def detect_bureau(cell: str | None) -> str | None:
    """Return canonical bureau name (e.g. '関東財務局') if cell carries
    a bureau header, else None.

    Cell values look like '関東財務局\n【計25業者】' or '近畿財務局\n【計2業者】'."""

    if not cell:
        return None
    flat = re.sub(r"\s+", "", cell)
    for kanji_name in BUREAU_LABELS:
        if kanji_name in flat:
            return kanji_name
    return None


def extract_latin_alias(name_kanji: str) -> str | None:
    """Pull the embedded Latin/ASCII brand name from a JFSA firm
    legal name, if any.

    The register mixes pure-Japanese names ('株式会社マネーパートナーズ'),
    Latin-bracketed legal names ('株式会社bitFlyer', 'SBI VCトレード株式会社',
    'Binance Japan株式会社', 'Coinbase株式会社', 'OSL Japan株式会社'),
    and pure-katakana transliterations ('コインチェック株式会社' = Coincheck,
    'ビットバンク株式会社' = Bitbank, 'ビットトレード株式会社' = Bittrade).

    We do NOT do automatic kana-to-roman conversion (would require a
    transliteration library and produce ambiguous romanisations).
    Instead we surface any embedded Latin run as a SECONDARY alias —
    the canonical entity_name remains the kanji legal name (DD-survivable,
    matches MoFA / 法人番号 corporate registry exactly).

    Latin alias is what the merge_vasp_directory alias-matcher uses to
    detect multi-jur overlap with FCA / FinCEN / NY DFS / MAS / VARA
    listings (e.g. JFSA 'Binance Japan株式会社' ↔ FinCEN 'Binance' / VARA
    'Binance MENA').

    Returns None when the name is purely Japanese (caller falls back to
    kanji name as the only label).
    """

    if not name_kanji:
        return None
    # Strip the 株式会社 prefix/suffix and ※-footnote markers
    stripped = re.sub(r"※\d*", "", name_kanji)
    stripped = stripped.replace("株式会社", "").strip()
    # Find runs of [A-Za-z][A-Za-z0-9 .&\-']* — keep the LONGEST since
    # short fragments like 'C' or 'X' inside katakana are noise.
    latin_runs = re.findall(r"[A-Za-z][A-Za-z0-9 .&'\-]*", stripped)
    if not latin_runs:
        return None
    longest = max(latin_runs, key=len).strip(" .-'")
    if len(longest) < 2:
        return None
    return longest


def parse_register(pdf_path: Path) -> tuple[list[JfsaFirm], int | None]:
    """Walk every table on every PDF page; emit one JfsaFirm per row.

    Returns (firms, declared_total) where declared_total is the
    `【全業者数：N】` number stamped on each page header (for sanity
    cross-check vs len(firms)).
    """

    firms: list[JfsaFirm] = []
    declared_total: int | None = None
    current_bureau: str | None = None

    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            m = re.search(r"【全業者数：([０-９0-9]+)】", text)
            if m and declared_total is None:
                declared_total = int(_zen_to_han(m.group(1)))

            for table in page.extract_tables():
                for row in table:
                    if row is None or len(row) < 9:
                        continue
                    bureau_cell = row[0]
                    license_cell = row[1] or ""
                    date_cell = row[2] or ""
                    name_cell = row[3] or ""
                    corp_cell = row[4] or ""
                    postal_cell = row[5] or ""
                    address_cell = row[6] or ""
                    phone_cell = row[7] or ""
                    assets_cell = row[8] or ""

                    # Skip header rows that recur on every page
                    if "登録番号" in license_cell:
                        # Allow this row to update bureau if present
                        bureau = detect_bureau(bureau_cell)
                        if bureau:
                            current_bureau = bureau
                        continue

                    # Update bureau if this row's 所管 column carries one
                    bureau = detect_bureau(bureau_cell)
                    if bureau:
                        current_bureau = bureau

                    # Skip rows that don't carry a 第NNNNN号 license number
                    if "第" not in license_cell or "号" not in license_cell:
                        continue

                    license_number, license_full, bureau_from_license = (
                        parse_license_number(license_cell)
                    )
                    if not license_number:
                        continue

                    # Bureau resolution priority:
                    #   1. Prefix on the license itself (always present in
                    #      the FSA register: '関東財務局長 第NNNNN号' /
                    #      '近畿財務局長 第NNNNN号'). This is the canonical
                    #      signal — every license_id row carries it.
                    #   2. Most-recent 所管 column header (fallback only;
                    #      Kanto bureau header is rendered as page text,
                    #      not a table cell, so 所管 is None on every
                    #      Kanto row in pdfplumber output).
                    bureau_resolved = bureau_from_license or current_bureau or ""

                    iso_date, wareki_raw = parse_wareki_date(date_cell)
                    # Strip ※-footnote markers (e.g. 'Binance Japan株式会社※1'
                    # carries a footnote pointer to the prior-license note;
                    # the marker is page-local metadata, not part of the
                    # legal name).
                    name_kanji = re.sub(r"※\d*", "", name_cell).strip()

                    bureau_slug, bureau_en = BUREAU_LABELS.get(
                        bureau_resolved, (bureau_resolved or "jfsa", bureau_resolved)
                    )

                    firms.append(
                        JfsaFirm(
                            license_number=license_number,
                            license_full=license_full,
                            bureau_kanji=bureau_resolved,
                            bureau_slug=bureau_slug,
                            bureau_en=bureau_en,
                            name_kanji=name_kanji,
                            latin_alias=extract_latin_alias(name_kanji),
                            corporate_number=(corp_cell or "").strip() or None,
                            postal_code=(postal_cell or "").strip() or None,
                            address_kanji=(address_cell or "").strip() or None,
                            phone=(phone_cell or "").strip() or None,
                            registration_date_iso=iso_date,
                            registration_date_wareki=wareki_raw,
                            supported_assets_kanji=(assets_cell or "").strip() or None,
                        )
                    )

    return firms, declared_total


def to_unified_record(firm: JfsaFirm, today: date) -> dict:
    # Address ID — bureau-scoped license number ensures uniqueness even
    # if two bureaus issue overlapping numeric IDs (近畿財務局 第00001号
    # = Zaif ≠ 関東財務局 第00001号 = Money Partners; both exist).
    addr = f"jp_jfsa::license_id::{firm.bureau_slug}_{firm.license_number}"

    # Canonical entity_name = full kanji legal name (DD-survivable; matches
    # MoFA / 法人番号 corporate registry exactly). Latin alias surfaces
    # alongside as a SECOND label entry so merge_vasp_directory's
    # alias-matcher can join JP firms to their multi-jur counterparts
    # (Binance Japan ↔ FinCEN Binance, Coinbase 株式会社 ↔ FinCEN
    # Coinbase Inc, etc.) without us inventing a one-word display name.
    labels = [
        {
            "name": firm.name_kanji,
            "type": "exchange",
            "source": "jp_jfsa_register",
            "chain": "multi",
        }
    ]
    if firm.latin_alias and firm.latin_alias != firm.name_kanji:
        labels.append(
            {
                "name": firm.latin_alias,
                "type": "exchange",
                "source": "jp_jfsa_register_latin_alias",
                "chain": "multi",
            }
        )

    return {
        "address": addr,
        "chain": "multi",
        "labels": labels,
        "is_exchange": True,
        "is_illicit": False,
        "is_ai_agent": False,
        "entity_name": firm.name_kanji,
        "category": "vasp",
        "jurisdiction": "JP",
        "license_id": firm.license_full,
        "regulator": "Financial Services Agency (JP FSA)",
        "license_status": "active",
        "sanctioned": False,
        "source_url": FSA_REGISTER_LANDING,
        "source_date": today.isoformat(),
        # Diagnostic / native-language fields (prefix `_jp_` to avoid
        # colliding with merge_vasp_directory canonical schema).
        "_jp_kanji_name": firm.name_kanji,
        "_jp_latin_alias": firm.latin_alias,
        "_jp_address": firm.address_kanji,
        "_jp_postal_code": firm.postal_code,
        "_jp_phone": firm.phone,
        "_jp_corporate_number": firm.corporate_number,
        "_jp_bureau_kanji": firm.bureau_kanji,
        "_jp_bureau_en": firm.bureau_en,
        "_jp_registration_date_iso": firm.registration_date_iso,
        "_jp_registration_date_wareki": firm.registration_date_wareki,
        "_jp_supported_assets": firm.supported_assets_kanji,
    }


def main() -> None:
    if pdfplumber is None:  # pragma: no cover
        print("ERROR: pdfplumber not installed — `pip install openlabels-core[jfsa]`.",
              file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / "labels_raw" /
        f"jp_jfsa_vasps_{date.today().isoformat()}.json",
    )
    parser.add_argument(
        "--pdf-cache",
        type=Path,
        default=Path("data") / "labels_raw" / "_jp_jfsa_register.pdf",
        help="Local cache path for the FSA register PDF",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Re-download even if --pdf-cache exists",
    )
    parser.add_argument(
        "--source-url",
        type=str,
        default=FSA_PDF_URL,
        help="FSA register PDF URL (override only for archival reruns)",
    )
    args = parser.parse_args()

    today = date.today()
    args.pdf_cache.parent.mkdir(parents=True, exist_ok=True)

    if args.force_download or not args.pdf_cache.exists():
        print(f"Downloading FSA register PDF: {args.source_url}", flush=True)
        fetch_pdf(args.source_url, args.pdf_cache)
        print(f"  cached at {args.pdf_cache} "
              f"({args.pdf_cache.stat().st_size:,} bytes)", flush=True)
    else:
        print(f"Using cached PDF: {args.pdf_cache} "
              f"({args.pdf_cache.stat().st_size:,} bytes)", flush=True)

    firms, declared_total = parse_register(args.pdf_cache)

    # Sanity check: parsed rows must equal the PDF's own header count.
    if declared_total is not None and len(firms) != declared_total:
        print(
            f"WARN: parsed {len(firms)} firms but PDF header declares "
            f"{declared_total}. Investigate before merge.",
            file=sys.stderr,
        )

    # Anti-padding rule: if pdfplumber returned zero rows (PDF format
    # changed, table-extraction fails), exit 2 so the caller sees a
    # hard failure rather than a silent empty file.
    if not firms:
        print(
            "ERROR: zero firms parsed from FSA register PDF. The PDF "
            "table layout may have changed. Check `--pdf-cache` "
            f"({args.pdf_cache}) manually and rerun.",
            file=sys.stderr,
        )
        sys.exit(2)

    records = [to_unified_record(f, today) for f in firms]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)

    print(f"\nDeclared in PDF header: {declared_total}")
    print(f"Parsed firms: {len(firms)}")
    print("\nTop 10 firms:")
    for f in firms[:10]:
        alias = f" / {f.latin_alias}" if f.latin_alias else ""
        print(
            f"  {f.bureau_kanji or '?':6s} {f.license_full[:24]:24s} "
            f"{f.name_kanji[:30]:30s}{alias:20s} reg={f.registration_date_iso}"
        )
    if len(firms) > 10:
        print(f"  … (+{len(firms) - 10} more)")

    # Multi-jur overlap candidates — firms whose Latin alias matches a
    # known multi-jur exchange family. Surfaced for multi-jurisdiction
    # coverage measurement.
    overlap_tags = (
        "bitFlyer", "Coinbase", "Binance", "GMO", "SBI",
        "OSL", "Gate", "LINE",
    )
    overlap_candidates = [
        f for f in firms
        if f.latin_alias and any(
            tag.lower() in f.latin_alias.lower() for tag in overlap_tags
        )
    ]
    overlap_candidates.sort(key=lambda f: f.license_number)
    if overlap_candidates:
        print(f"\nMulti-jur overlap candidates ({len(overlap_candidates)}):")
        for f in overlap_candidates:
            print(f"  {f.license_full[:24]:24s} {f.name_kanji} → "
                  f"alias '{f.latin_alias}'")

    print(f"\nOutput: {args.output}")


if __name__ == "__main__":
    main()
