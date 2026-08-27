#!/usr/bin/env python3
"""HK SFC Public Register VATP licensee scraper.

Source: https://apps.sfc.hk/publicregWeb/searchByRa
        (form action -> /publicregWeb/searchByRaJson)

Why iterate by name-prefix letter (not bulk dump):
The SFC public register is a Java/ExtJS app whose search form requires a
`nameStartLetter` field (allowBlank: false in the form definition). There
is no `?all=true` style bulk endpoint exposed publicly. The total VATP
universe is tiny (~17 corporations as of 2026-05-15), so iterating
A..Z + 0..9 with `roleType=corporation` + `ratypeamlo=101`
(AMLO Schedule 3B – "Operating a virtual asset trading platform") yields
the complete enumerable universe in 36 cheap POSTs.

Per-corporation enrichment:
  GET /publicregWeb/corp/{ceref}/details
The page embeds two JS literals — `raDetailData` (SFO licence rows) and
`amloDetailData` (AMLO licence rows). For VATPs the AMLO row carries the
operative effective date and active/expired flag. We parse these inline
JSON fragments with a tolerant regex (no headless browser needed).

License status mapping:
  hasActiveLicenceAmlo=Y, isDeemedLicenceAmlo=N  -> "active"   (full licence)
  hasActiveLicenceAmlo=N, isDeemedLicenceAmlo=Y  -> "pending"  (deemed under
                                                    AMLO Sched. 3B
                                                    transitional regime)
  hasActiveLicenceAmlo=Y, isDeemedLicenceAmlo=Y  -> "active"   (full,
                                                    notation kept in
                                                    _hk_is_deemed)
  amloDetailData[].status == 'A'  -> active
  amloDetailData[].status == 'E'  -> expired/revoked

Output schema mirrors fca_register_vasps_*.json + scrape_fca_register.py
to keep merge_vasp_directory.py untouched.
"""

from __future__ import annotations

import argparse
import json
import re
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

REGISTER_BASE = "https://apps.sfc.hk/publicregWeb"
SEARCH_URL = f"{REGISTER_BASE}/searchByRaJson"
SEARCH_REFERER = f"{REGISTER_BASE}/searchByRa"
DETAIL_URL_TEMPLATE = f"{REGISTER_BASE}/corp/{{ceref}}/details"
PUBLIC_DETAIL_URL_TEMPLATE = f"{REGISTER_BASE}/corp/{{ceref}}/details"

# Form parameter values (verified by reading
# https://apps.sfc.hk/publicregWeb/searchByRa source 2026-05-15):
#   ratypeamlo=101  -> AMLO Schedule 3B Type 101
#                       "Operating a virtual asset trading platform"
#   licstatus=all   -> include both active and deemed/pending
#   roleType=corporation -> exclude individuals (no individual VATPs exist)
RATYPE_AMLO_VATP = "101"

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
)

# Inline JS-literal regex for the embedded amloDetailData / raDetailData
# arrays in the corp/{ceref}/details page. The arrays are emitted as JSON
# but with literal NUL bytes inside string values (raCategory:"")
# which json.loads can swallow but downstream tools cannot — strip them.
_AMLO_DATA_RE = re.compile(
    r"var\s+amloDetailData\s*=\s*(\[.*?\]);", re.DOTALL
)
_SFO_DATA_RE = re.compile(
    r"var\s+raDetailData\s*=\s*(\[.*?\]);", re.DOTALL
)
# Address line: "<p>Corporation:<span> NAME  CHIN_NAME</span><span> (CEREF)</span>"
_ADDRESS_LINE_RE = re.compile(
    r"<p>\s*Corporation:\s*<span>(.+?)</span>\s*<span>\s*\(([A-Z0-9]+)\)\s*</span>",
    re.DOTALL,
)


@dataclass(frozen=True)
class HkSfcFirm:
    ceref: str
    name: str
    name_chi: str | None
    address_full: str | None
    has_active_amlo: bool
    is_deemed_amlo: bool
    has_active_sfo: bool
    amlo_eff_date: str | None        # ISO yyyy-mm-dd
    amlo_status_code: str | None     # 'A' | 'E' | None
    sfo_act_types: tuple[int, ...]   # e.g. (1, 7) for "Dealing in Securities"
                                     # + "Providing Automated Trading Services"


class HkSfcClient:
    """Stdlib-only client with retry + cookie persistence."""

    def __init__(self, sleep: float = 0.6):
        self._sleep = sleep
        self._cookies: dict[str, str] = {}
        # Prime cookies by GETting the search page once. The Java backend
        # tracks JSESSIONID + a few BIGip/TS load-balancer cookies; the
        # search POST will fail without them.
        self._prime()

    # ------------------------- low-level -------------------------

    def _cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())

    def _store_cookies(self, response) -> None:
        # Set-Cookie can repeat; urllib gives them as a list of headers.
        for raw in response.headers.get_all("Set-Cookie") or []:
            kv = raw.split(";", 1)[0]
            if "=" in kv:
                k, v = kv.split("=", 1)
                self._cookies[k.strip()] = v.strip()

    def _request(
        self,
        url: str,
        method: str = "GET",
        body: bytes | None = None,
        extra_headers: dict | None = None,
        retries: int = 4,
    ) -> bytes:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }
        if extra_headers:
            headers.update(extra_headers)
        if self._cookies:
            headers["Cookie"] = self._cookie_header()

        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    url, data=body, headers=headers, method=method
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    self._store_cookies(resp)
                    return resp.read()
            except (urllib.error.URLError, TimeoutError) as exc:
                last_exc = exc
                # Backoff: 1.0, 2.0, 4.0, 8.0
                time.sleep(2 ** attempt)
        raise RuntimeError(f"GET/POST {url} failed after {retries}: {last_exc}")

    def _prime(self) -> None:
        # GET search page to seed JSESSIONID + load-balancer cookies.
        self._request(SEARCH_REFERER, method="GET")

    # ------------------------- public -------------------------

    def search_letter(self, letter: str) -> list[dict]:
        body = urllib.parse.urlencode(
            {
                "ratypeamlo": RATYPE_AMLO_VATP,
                "licstatus": "all",
                "roleType": "corporation",
                "nameStartLetter": letter,
                "page": "1",
                "start": "0",
                "limit": "50",
            }
        ).encode("utf-8")
        raw = self._request(
            SEARCH_URL,
            method="POST",
            body=body,
            extra_headers={
                "Content-Type": (
                    "application/x-www-form-urlencoded; charset=UTF-8"
                ),
                "X-Requested-With": "XMLHttpRequest",
                "Referer": SEARCH_REFERER,
                "Origin": "https://apps.sfc.hk",
                "Accept": "*/*",
            },
        )
        text = raw.decode("utf-8", errors="replace").replace("\x00", "")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"searchByRaJson letter={letter!r} returned non-JSON: "
                f"{text[:200]!r}"
            ) from exc
        time.sleep(self._sleep)
        return payload.get("items") or []

    def fetch_corp_details(self, ceref: str) -> str:
        raw = self._request(
            DETAIL_URL_TEMPLATE.format(ceref=ceref),
            method="GET",
            extra_headers={"Referer": SEARCH_REFERER},
        )
        time.sleep(self._sleep)
        return raw.decode("utf-8", errors="replace").replace("\x00", "")


# ------------------------- parsing helpers -------------------------


def _parse_sfc_date(value: str | None) -> str | None:
    """Convert "Apr 19, 2024 12:00:00 AM" -> "2024-04-19"."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d, %Y %I:%M:%S %p").date().isoformat()
    except ValueError:
        # Try fallback formats (just in case the upstream format ever drifts)
        for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%b %d, %Y"):
            try:
                return datetime.strptime(value, fmt).date().isoformat()
            except ValueError:
                continue
    return None


def parse_corp_details_html(html: str) -> tuple[
    str | None, str | None, list[dict], list[dict]
]:
    """Return (full_address, name_chi_or_None, sfo_rows, amlo_rows)."""
    sfo_rows: list[dict] = []
    amlo_rows: list[dict] = []

    m = _AMLO_DATA_RE.search(html)
    if m:
        try:
            amlo_rows = json.loads(m.group(1))
        except json.JSONDecodeError:
            amlo_rows = []

    m = _SFO_DATA_RE.search(html)
    if m:
        try:
            sfo_rows = json.loads(m.group(1))
        except json.JSONDecodeError:
            sfo_rows = []

    # The corp details HTML in the SFC register doesn't include the
    # full registered address (that's on the search-result row only).
    # Return placeholder.
    return None, None, sfo_rows, amlo_rows


def to_hk_firm(item: dict, details_html: str | None) -> HkSfcFirm:
    ceref = item["ceref"]
    name = (item.get("name") or "").strip()
    name_chi = (item.get("nameChi") or "").strip() or None
    if name_chi == "":
        name_chi = None

    addr = item.get("address") or {}
    address_full = (addr.get("fullAddress") or None) if addr else None

    has_active_amlo = item.get("hasActiveLicenceAmlo") == "Y"
    is_deemed_amlo = item.get("isDeemedLicenceAmlo") == "Y"
    has_active_sfo = item.get("hasActiveLicence") == "Y"

    amlo_eff_date: str | None = None
    amlo_status_code: str | None = None
    sfo_act_types: tuple[int, ...] = ()

    if details_html:
        _, _, sfo_rows, amlo_rows = parse_corp_details_html(details_html)
        # AMLO row matching VATP actType=101
        for row in amlo_rows:
            if int(row.get("actType") or 0) == int(RATYPE_AMLO_VATP):
                amlo_eff_date = _parse_sfc_date(row.get("effDate"))
                amlo_status_code = row.get("status")
                break
        sfo_act_types = tuple(
            sorted({int(r.get("actType") or 0) for r in sfo_rows
                    if r.get("actType") is not None})
        )

    return HkSfcFirm(
        ceref=ceref,
        name=name,
        name_chi=name_chi,
        address_full=address_full,
        has_active_amlo=has_active_amlo,
        is_deemed_amlo=is_deemed_amlo,
        has_active_sfo=has_active_sfo,
        amlo_eff_date=amlo_eff_date,
        amlo_status_code=amlo_status_code,
        sfo_act_types=sfo_act_types,
    )


def to_unified_record(firm: HkSfcFirm, today: date) -> dict:
    # Status mapping. Precedence: amlo_status_code from details (if available)
    # otherwise fall back to search-row flags.
    license_status = "active"
    if firm.amlo_status_code == "E":
        license_status = "revoked"
    elif firm.amlo_status_code == "A":
        license_status = "active"
    elif firm.has_active_amlo:
        license_status = "active"
    elif firm.is_deemed_amlo:
        license_status = "pending"
    elif not firm.has_active_amlo and not firm.is_deemed_amlo:
        # Possible if a firm appeared in the AMLO-101 universe historically
        # then dropped — keep as 'revoked' rather than 'unknown' so the
        # downstream merge/JOIN does not need a new label.
        license_status = "revoked"

    return {
        "address": f"hk_sfc::license_id::{firm.ceref}",
        "chain": "multi",
        "labels": [
            {
                "name": firm.name,
                "type": "exchange",
                "source": "hk_sfc_register",
                "chain": "multi",
            }
        ],
        "is_exchange": True,
        "is_illicit": False,
        "is_ai_agent": False,
        "entity_name": firm.name,
        "category": "vasp",
        "jurisdiction": "HK",
        "license_id": firm.ceref,
        "regulator": "Securities and Futures Commission (HK SFC)",
        "license_status": license_status,
        "sanctioned": False,
        "source_url": PUBLIC_DETAIL_URL_TEMPLATE.format(ceref=firm.ceref),
        "source_date": today.isoformat(),
        "_hk_ceref": firm.ceref,
        "_hk_name_chi": firm.name_chi,
        "_hk_address": firm.address_full,
        "_hk_has_active_amlo": firm.has_active_amlo,
        "_hk_is_deemed_amlo": firm.is_deemed_amlo,
        "_hk_has_active_sfo": firm.has_active_sfo,
        "_hk_amlo_effective_date": firm.amlo_eff_date,
        "_hk_amlo_status_code": firm.amlo_status_code,
        "_hk_sfo_act_types": list(firm.sfo_act_types),
    }


# ------------------------- collect -------------------------


@dataclass
class CollectStats:
    letters_searched: int = 0
    letters_with_hits: int = 0
    raw_hits: int = 0
    enriched: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)


def collect(
    client: HkSfcClient, letters: list[str]
) -> tuple[list[HkSfcFirm], CollectStats]:
    seen: dict[str, dict] = {}
    stats = CollectStats()

    for L in letters:
        stats.letters_searched += 1
        try:
            items = client.search_letter(L)
        except Exception as exc:
            stats.errors.append((f"search:{L}", str(exc)))
            continue
        if items:
            stats.letters_with_hits += 1
        for it in items:
            stats.raw_hits += 1
            ceref = it.get("ceref")
            if not ceref:
                continue
            # Last-write-wins is fine — every letter that returns a row
            # carries identical row data for that ceref.
            seen[ceref] = it

    firms: list[HkSfcFirm] = []
    for ceref, item in seen.items():
        try:
            html = client.fetch_corp_details(ceref)
        except Exception as exc:
            stats.errors.append((f"detail:{ceref}", str(exc)))
            html = None
        firms.append(to_hk_firm(item, html))
        stats.enriched += 1
    return firms, stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data") / "labels_raw" /
        f"hk_sfc_vasps_{date.today().isoformat()}.json",
    )
    parser.add_argument("--sleep", type=float, default=0.6)
    parser.add_argument(
        "--letters",
        type=str,
        default=string.ascii_uppercase + string.digits,
        help="Override the letter set (debug only).",
    )
    args = parser.parse_args()

    letters = list(args.letters)
    today = date.today()
    client = HkSfcClient(sleep=args.sleep)

    print(
        f"Iterating {len(letters)} name-prefix queries against "
        f"{SEARCH_URL} (ratypeamlo=101) …",
        flush=True,
    )
    firms, stats = collect(client, letters)
    if stats.errors:
        # If every search letter failed, we have nothing to write — refuse
        # to produce an empty file masquerading as a real scrape.
        if stats.letters_with_hits == 0 and stats.letters_searched > 0:
            print(
                f"\nERROR: every letter search failed "
                f"({len(stats.errors)} errors). Sample: {stats.errors[:3]}",
                file=sys.stderr,
            )
            sys.exit(2)

    records = [to_unified_record(f, today) for f in firms]
    # Stable order: ceref ascending so successive runs diff cleanly.
    records.sort(key=lambda r: r["license_id"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)

    print(f"\nLetters searched   : {stats.letters_searched}")
    print(f"Letters with hits  : {stats.letters_with_hits}")
    print(f"Raw hits (sum)     : {stats.raw_hits}")
    print(f"Unique enriched    : {stats.enriched}")
    print(f"Errors             : {len(stats.errors)}")

    print(
        f"\nFirms (alphabetical by license_id, "
        f"showing first {min(10, len(firms))}):"
    )
    for r in records[:10]:
        print(
            f"  {r['license_id']:8s}  "
            f"{r['entity_name'][:55]:55s}  "
            f"status={r['license_status']:8s}  "
            f"eff={r.get('_hk_amlo_effective_date')}"
        )
    if stats.errors:
        print(f"\nErrors (first 10 of {len(stats.errors)}):")
        for src, msg in stats.errors[:10]:
            print(f"  - {src}: {msg[:120]}")
    print(f"\nOutput: {args.output}")


if __name__ == "__main__":
    main()
