#!/usr/bin/env python3
"""Parse OFAC recent-actions HTML pages and each individual action page →
extract cryptocurrency addresses with attribution.

Workflow:
  1. Read index HTML files (ofac_recent_YYYY_pN.html) in data/labels_raw/.
  2. Extract all /recent-actions/<id> links.
  3. For each action page, download HTML (if not cached).
  4. Extract: entity name (from <h1>), program (IRGC / RUSSIA-EO14024 / ...),
     publication date, ALL cryptocurrency addresses matched by regex.
  5. Attribute each address to that entity + action page as source_url.
  6. Emit raw JSON compatible with merge_to_unified.py.

Output: data/labels_raw/ofac_press_releases_parsed.json
"""

from __future__ import annotations

import argparse
import hashlib
import html as htmlmod
import json
import re
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path

from openlabels.bitcoin_address import is_base58check
from openlabels.ofac_attributed import _infer_chain
from openlabels.tron_address import _b58decode

HEX_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
TRON_B58_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
BTC_LEGACY_RE = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")
# bech32/bech32m: P2WPKH is 42 chars, P2WSH and taproot 62, the spec allows 90. The old
# {38,58} cap missed every 62-character address (8 on the cached OFAC pages, 2026-09-14).
BTC_BECH32_RE = re.compile(r"\bbc1[02-9ac-hj-np-z]{38,87}\b")
LTC_RE = re.compile(r"\b(ltc1[02-9ac-hj-np-z]{38,58}|[LM][1-9A-HJ-NP-Za-km-z]{25,34})\b")
XMR_RE = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94,105}\b")

ACTION_LINK_RE = re.compile(r'href="(/recent-actions/[0-9a-zA-Z_\-\.]+)"')
# OFAC prints every listed address with its ticker: "Digital Currency Address - ETH 0x…";
# "alt. Digital Currency Address - ARB 0x…" repeats the same address per chain.
# Contract S (S2, 2026-09-14): the token is read whole — the old {20,90} cap cut every
# 95-character Monero address at 90 and the cut string became a second, phantom
# "sanctioned" address (7 on the cached pages). A matched token must then LOOK like an
# address of the inferred chain (_shape_ok); an unknown ticker is never guessed by shape.
TICKER_ADDR_RE = re.compile(r"Digital Currency Address\s*-\s*([A-Z]{2,8})\s+([A-Za-z0-9]{20,120})")
_EVM_LIKE = {
    "ethereum",
    "ethereum_classic",
    "arbitrum",
    "bsc",
    "base",
    "optimism",
    "polygon",
    "gnosis",
    "avalanche_c",
}


# Contract R (code review 2026-09-15, MEDIUM-2): a base58 REGEX is not an address test.
# Pre-2018 OFAC pages carry base64 blobs (inline images, signatures) whose substrings match
# the legacy Bitcoin/Litecoin shapes; 37 such fragments sat in the store as `sanctioned`
# "addresses" (17 bitcoin + 20 litecoin). Legacy base58check addresses carry a 4-byte
# checksum — a candidate that fails it is not an address. Litecoin legacy versions: 0x30
# (L…), 0x32 (M…), 0x05 (3…, deprecated P2SH shared with Bitcoin).
_LTC_LEGACY_VERSIONS = frozenset({0x30, 0x32, 0x05})
# OFAC's first digital-currency designation (Mohammad Ghorbaniyan / Ali Khorashadizadeh,
# 2018-11-28): an "address" on an action page dated earlier is not an address.
FIRST_CRYPTO_ACTION_DATE = "2018-11-28"


def _b58check_payload(addr: str) -> bytes | None:
    """The 25-byte base58check payload of `addr`, or None when it does not decode / the
    checksum fails."""
    try:
        raw = _b58decode(addr)
    except ValueError:
        return None
    if len(raw) != 25:
        return None
    if hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] != raw[21:]:
        return None
    return raw


def _litecoin_legacy_ok(addr: str) -> bool:
    raw = _b58check_payload(addr)
    return raw is not None and raw[0] in _LTC_LEGACY_VERSIONS


def _shape_ok(chain: str, addr: str) -> bool:
    """False when a ticker-attributed token is not an address of that chain."""
    if chain in _EVM_LIKE:
        return HEX_RE.fullmatch(addr) is not None
    if chain == "tron":
        return TRON_B58_RE.fullmatch(addr) is not None
    if chain == "bitcoin":
        if BTC_BECH32_RE.fullmatch(addr) is not None:
            return True
        return BTC_LEGACY_RE.fullmatch(addr) is not None and is_base58check(addr)
    if chain == "litecoin":
        if addr.lower().startswith("ltc1"):
            return LTC_RE.fullmatch(addr) is not None
        return LTC_RE.fullmatch(addr) is not None and _litecoin_legacy_ok(addr)
    if chain == "monero":
        return XMR_RE.fullmatch(addr) is not None
    return True  # no fixed format known here (zcash, dash, solana, …)


def extract_action_links(index_dir: Path) -> list[str]:
    links: set[str] = set()
    # 1. Drupal-rendered index HTMLs (noisy, fragmented — ~35 links)
    for f in sorted(index_dir.glob("ofac_recent_*.html")):
        text = f.read_text(encoding="utf-8", errors="ignore")
        for m in ACTION_LINK_RE.finditer(text):
            links.add(m.group(1))
    # 2. Sitemap.xml — the real source of truth (~3000 links incl. history)
    sitemap_path = index_dir / "ofac_sitemap.xml"
    if sitemap_path.exists():
        text = sitemap_path.read_text(encoding="utf-8", errors="ignore")
        sitemap_re = re.compile(
            r"<loc>https://ofac\.treasury\.gov(/recent-actions/[0-9a-zA-Z_\-\.]+)</loc>"
        )
        for m in sitemap_re.finditer(text):
            links.add(m.group(1))
    return sorted(links)


def fetch_action_page(url_path: str, cache_dir: Path) -> str | None:
    """Download action page to cache, return HTML text."""
    # Stable cache name based on url path
    sha = hashlib.sha1(url_path.encode()).hexdigest()[:12]
    slug = url_path.rsplit("/", 1)[-1].replace("?", "_").replace("&", "_")[:60]
    cache_name = f"action_{slug}_{sha}.html"
    cache_path = cache_dir / cache_name
    if cache_path.exists() and cache_path.stat().st_size > 500:
        return cache_path.read_text(encoding="utf-8", errors="ignore")
    full_url = f"https://ofac.treasury.gov{url_path}"
    try:
        r = subprocess.run(
            [
                "curl",
                "-sL",
                "--max-time",
                "30",
                "-A",
                "Mozilla/5.0 (compatible; AIDecisionsBot/1.0)",
                full_url,
            ],
            capture_output=True,
            text=True,
            timeout=35,
        )
        if r.returncode != 0 or not r.stdout or len(r.stdout) < 500:
            return None
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(r.stdout, encoding="utf-8")
        time.sleep(0.3)  # polite — 3 req/sec per worker, 2 workers → 6 req/sec
        return r.stdout
    except Exception:
        return None


def fetch_action_page_concurrent(
    links: list[str],
    cache_dir: Path,
    max_workers: int = 4,
) -> dict[str, str]:
    """Concurrent download with bounded parallelism.

    Returns {url_path: html} for successfully fetched pages. Politeness:
    per-worker 0.3s sleep + max_workers=4 → peak 13 req/sec (OFAC handles
    Google indexer traffic, this is fine).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(fetch_action_page, link, cache_dir): link for link in links}
        for i, fut in enumerate(as_completed(futures)):
            link = futures[fut]
            try:
                html = fut.result()
            except Exception:
                html = None
            if html:
                results[link] = html
            if (i + 1) % 100 == 0:
                print(f"  fetched {i+1}/{len(links)} (ok={len(results)})", flush=True)
    return results


def extract_addresses_from_html(html: str) -> dict[str, set[str]]:
    """Mine all crypto addresses from HTML body text."""
    out: dict[str, set[str]] = {}
    for m in TRON_B58_RE.finditer(html):
        # Must also filter out false positives that look like TRON but are
        # English words or CSS classes. Heuristic: base58check first byte is
        # 0x41 for Tron mainnet, so `T` is valid. Length 34 exact.
        addr = m.group(0)
        if len(addr) == 34:
            out.setdefault("tron", set()).add(addr)
    for m in HEX_RE.finditer(html):
        out.setdefault("ethereum", set()).add(m.group(0).lower())
    for m in BTC_BECH32_RE.finditer(html):
        out.setdefault("bitcoin", set()).add(m.group(0).lower())
    for m in BTC_LEGACY_RE.finditer(html):
        addr = m.group(0)
        # Filter out things that match pattern but are words in a sentence.
        # Conservative: accept only if there's no adjacent alpha char.
        out.setdefault("bitcoin", set()).add(addr)
    for m in LTC_RE.finditer(html):
        out.setdefault("litecoin", set()).add(
            m.group(0).lower() if m.group(0).startswith("ltc1") else m.group(0)
        )
    for m in XMR_RE.finditer(html):
        out.setdefault("monero", set()).add(m.group(0))
    return out


def _norm_addr(addr: str) -> str:
    return addr.lower() if addr.startswith("0x") else addr


# --- OFAC page sections (contract R / Q1, 2026-09-15) -----------------------------------
# An OFAC "recent action" page lists the day's SDN changes under section headers of the
# form "The following <individuals|entities|deletions|changes> have been <added to|made
# to> OFAC's SDN List:". Every address occurrence belongs to the section whose header
# precedes it, and the section decides what OFAC DID with the address that day:
#   designation — "…have been added to OFAC's SDN List" (a new listing)
#   change      — "…changes have been made to…", "…updated to include the following
#                 language…" (the listing is amended and still in force)
#   removal     — "…deletions have been made to…", "…removed from…" (the listing ends)
# Before this, every address on every page became a `sanctioned` label: 91 addresses
# whose LAST OFAC action was a deletion (Tornado Cash, 2025-03-21) stayed `sanctioned`
# in the store while the live SDN no longer carried them (measured 2026-09-14).
ACTION_DESIGNATION = "designation"
ACTION_CHANGE = "change"
ACTION_REMOVAL = "removal"
# When one page lists an address under two sections (2022-11-08: Tornado Cash deleted
# and re-designated the same day) the page's net action is the strongest listing act.
_ACTION_PRIORITY = {ACTION_DESIGNATION: 2, ACTION_CHANGE: 1, ACTION_REMOVAL: 0}
SECTION_HEADER_RE = re.compile(
    r"(?:(?:In addition|Lastly|Finally|Also),\s*|On \d{1,2}/\d{1,2}/\d{4},?\s*)?"
    r"(?:[Tt]he following|[Tt]he names below|OFAC has updated the following)"
    r"[^<>\n]{0,240}?:\s*(?=<|\n|$)"
)
_SLUG_DATE_RE = re.compile(r"(\d{4})(\d{2})(\d{2})")


def classify_section_header(header: str) -> str | None:
    """The action a section header announces, or None when the sentence is not a section
    (an introduction naming several kinds of change at once: "…the following additions,
    removals, and changes have been made…" opens no section by itself)."""
    # the connective is not the act: "In addition, the following changes…" is a change
    low = re.sub(r"^\s*(?:in addition|lastly|finally|also),?\s*", "", header.lower())
    removal = "deletion" in low or "removed" in low or "removal" in low
    addition = "added" in low or "addition" in low
    change = "change" in low or "updated" in low or "amended" in low
    if "language" in low or "names below" in low or "below names" in low:
        # wording added to EXISTING entries ("…has been added to the below names") is an
        # amendment of listings still in force, not a new designation
        return ACTION_CHANGE
    if removal and addition:
        return None
    if removal:
        return ACTION_REMOVAL
    if addition:
        return ACTION_DESIGNATION
    if change:
        return ACTION_CHANGE
    return None


def _section_offsets(text: str) -> list[tuple[int, str]]:
    """(offset, action) of every section header in the page text, in page order."""
    out: list[tuple[int, str]] = []
    for m in SECTION_HEADER_RE.finditer(text):
        action = classify_section_header(m.group(0))
        if action is not None:
            out.append((m.start(), action))
    return out


def _action_at(offset: int, sections: list[tuple[int, str]]) -> tuple[str, str]:
    """(action, action_evidence) for an address occurrence at `offset`: the last section
    header before it ("section"), else designation with evidence "none" — an address
    mentioned before any section header is treated as listed (the pre-2026-09-15 reading)."""
    current: str | None = None
    for start, action in sections:
        if start < offset:
            current = action
        else:
            break
    if current is None:
        return ACTION_DESIGNATION, "none"
    return current, "section"


def net_action(actions: Iterable[str]) -> str:
    """The page's net action for one address: designation > change > removal."""
    acts = list(actions)
    if not acts:
        return ACTION_DESIGNATION
    return max(acts, key=lambda a: _ACTION_PRIORITY.get(a, -1))


def action_date_from_link(link: str, page_date: str) -> str:
    """OFAC action pages are named by day (/recent-actions/20250321); the day in the URL
    is the action date, the page's own date field is the fallback."""
    m = _SLUG_DATE_RE.search(link.rsplit("/", 1)[-1])
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    # the page's own date may be M/D/YYYY ("Release Date: 3/21/2025") — dates compare as
    # strings downstream, so the fallback is normalised to ISO (audit 2026-09-15 LOW-1)
    us = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", page_date.strip()) if page_date else None
    if us:
        return f"{us.group(3)}-{int(us.group(1)):02d}-{int(us.group(2)):02d}"
    return page_date


def _iter_shape_matches(text: str) -> Iterable[tuple[str, str, int]]:
    """(chain, address, offset) for every address the shape regexes find — the same
    matches `extract_addresses_from_html` collects, with their positions."""
    for m in TRON_B58_RE.finditer(text):
        if len(m.group(0)) == 34:
            yield "tron", m.group(0), m.start()
    for m in HEX_RE.finditer(text):
        yield "ethereum", m.group(0).lower(), m.start()
    for m in BTC_BECH32_RE.finditer(text):
        yield "bitcoin", m.group(0).lower(), m.start()
    for m in BTC_LEGACY_RE.finditer(text):
        if is_base58check(m.group(0)):  # a shape match with a bad checksum is not an address
            yield "bitcoin", m.group(0), m.start()
    for m in LTC_RE.finditer(text):
        a = m.group(0)
        if a.lower().startswith("ltc1"):
            yield "litecoin", a.lower(), m.start()
        elif _litecoin_legacy_ok(a):
            yield "litecoin", a, m.start()
    for m in XMR_RE.finditer(text):
        yield "monero", m.group(0), m.start()


def extract_address_actions(
    html: str, stats: dict[str, int] | None = None
) -> dict[str, dict[str, dict]]:
    """{address: {chain: {"evidence": "ticker"|"shape", "actions": [...], "action": net,
    "action_evidence": "section"|"none"}}} — the chain evidence of
    `extract_addresses_with_evidence` plus the OFAC page SECTION each occurrence sits in.
    `actions` lists every section the address appears under on this page (sorted);
    `action` is the page's net action for the address (designation > change > removal);
    `action_evidence` is "section" when at least one occurrence follows a section header."""
    text = htmlmod.unescape(html)
    sections = _section_offsets(text)
    out: dict[str, dict[str, dict]] = {}
    stats = stats if stats is not None else {}
    unknown_ticker: set[str] = set()

    def _add(addr: str, chain: str, evidence: str, offset: int) -> None:
        action, how = _action_at(offset, sections)
        slot = out.setdefault(addr, {}).setdefault(
            chain, {"evidence": evidence, "_actions": set(), "_section_seen": False}
        )
        slot["_actions"].add(action)
        slot["_section_seen"] = slot["_section_seen"] or how == "section"

    for m in TICKER_ADDR_RE.finditer(text):
        ticker, addr = m.group(1), m.group(2)
        chain = _infer_chain(ticker, addr)
        if chain == "unknown":
            # a ticker the inference does not know — no guess, not even by shape below
            unknown_ticker.add(_norm_addr(addr))
            stats["skipped_unknown_ticker"] = stats.get("skipped_unknown_ticker", 0) + 1
            print(
                f"ERROR parse_ofac_press_releases: unknown ticker {ticker!r} for {addr[:24]}… — "
                "skipped, no guess",
                file=sys.stderr,
            )
            continue
        if not _shape_ok(chain, addr):
            stats["skipped_shape_mismatch"] = stats.get("skipped_shape_mismatch", 0) + 1
            print(
                f"ERROR parse_ofac_press_releases: {ticker} token {addr[:24]}… (len {len(addr)}) is "
                f"not a {chain} address — skipped",
                file=sys.stderr,
            )
            continue
        _add(_norm_addr(addr), chain, "ticker", m.start(2))
    # the shape pass reads the same unescaped text as the ticker pass (an entity-encoded
    # address was found by one and missed by the other — security audit R16)
    ticker_keys = set(out)
    for chain, addr, offset in _iter_shape_matches(text):
        key = _norm_addr(addr)
        if key in ticker_keys:
            continue
        if key in unknown_ticker:
            stats["skipped_unknown_ticker"] = stats.get(
                "skipped_unknown_ticker", 0
            )  # counted above
            continue
        _add(key, chain, "shape", offset)
    for chains in out.values():
        for slot in chains.values():
            actions = slot.pop("_actions")
            slot["actions"] = sorted(actions)
            slot["action"] = net_action(actions)
            slot["action_evidence"] = "section" if slot.pop("_section_seen") else "none"
    return out


def page_net_action(chains: dict[str, dict]) -> tuple[str, str, list[str]]:
    """(net action, action_evidence, all sections seen) for one address over every chain
    the page lists it under — the address is one listing whatever tickers it carries."""
    actions: set[str] = set()
    evidence = "none"
    for slot in chains.values():
        actions.update(slot["actions"])
        if slot["action_evidence"] == "section":
            evidence = "section"
    return net_action(actions), evidence, sorted(actions)


def extract_addresses_with_evidence(
    html: str, stats: dict[str, int] | None = None
) -> dict[str, set[tuple[str, str]]]:
    """{address: {(chain, evidence)}} — chain from the ticker OFAC prints next to the
    address ("ticker", via the shape-first inference shared with the SDN parser; one
    address listed under ETH, ARB and BSC yields three chains), else from the address
    format alone ("shape", the pre-2026-09-14 behaviour, kept only for addresses OFAC
    mentions without a ticker). Contract P: every 0x used to be "ethereum" whatever
    OFAC wrote — SIM Hyon Sop's 0x4f47bc… lost its ARB and BSC listings.
    Contract R: the section-aware `extract_address_actions` is the producer; this is
    its chain/evidence projection."""
    return {
        addr: {(chain, slot["evidence"]) for chain, slot in chains.items()}
        for addr, chains in extract_address_actions(html, stats).items()
    }


def press_release_label(
    chain: str,
    slot: dict,
    *,
    title: str,
    source_url: str,
    action: str,
    action_evidence: str,
    sections: list[str],
    action_date: str,
) -> dict:
    """One `ofac_press_release` label for (address, chain) on one page. A removal page
    yields `type: sanctions_removed` — the label records the act OFAC published, and the
    listing act it ends is a different label (from the designation page). `context` keeps
    the page identity the label came from: 184 addresses sit on more than one page and the
    record-level `source_url` names only one of them."""
    return {
        "name": title[:200],
        "type": "sanctions_removed" if action == ACTION_REMOVAL else "sanctioned",
        "source": "ofac_press_release",
        "chain": chain,
        "chain_evidence": slot["evidence"],
        "context": {
            "source_url": source_url,
            "action": action,
            "action_date": action_date,
            "action_evidence": action_evidence,
            "sections": sections,
        },
    }


def press_release_records(
    addr: str,
    chains: dict[str, dict],
    *,
    title: str,
    source_url: str,
    link: str,
    action_date: str,
    page_date: str,
    programs: list[str],
    sanctions_ref: str,
) -> list[tuple[str, dict]]:
    """Raw records (one per chain) for one address on one page. On a removal page the
    record asserts nothing illicit: `sanctioned` False, `is_illicit` False, no category —
    the merge derives the record's standing from ALL its dated press-release labels
    (`reconcile_press_release_status`)."""
    action, action_evidence, sections = page_net_action(chains)
    listed = action != ACTION_REMOVAL
    out: list[tuple[str, dict]] = []
    for chain, slot in sorted(chains.items()):
        rec = {
            "address": addr,
            "chain": chain,
            "labels": [
                press_release_label(
                    chain,
                    slot,
                    title=title,
                    source_url=source_url,
                    action=action,
                    action_evidence=action_evidence,
                    sections=sections,
                    action_date=action_date,
                )
            ],
            "is_illicit": listed,
            "is_exchange": False,
            "is_ai_agent": False,
            "entity_name": title[:200],
            "category": "sanctioned" if listed else None,
            "sanctioned": listed,
            "sanctions_reference": sanctions_ref,
            "source_url": source_url,
            "source_date": page_date,
            "_ofac_pr_link": link,
            "_ofac_pr_programs": programs,
        }
        out.append((chain, rec))
    return out


def extract_entity_and_program(html: str) -> tuple[str, list[str], str]:
    """Get primary entity name, OFAC program tags, publication date."""
    # <h1> usually has action title. Contract S (S2/R14): without a closing tag the lazy
    # search is quadratic in the number of "<h1" occurrences — skip it on a torn page.
    m = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.DOTALL) if "</h1>" in html else None
    title = ""
    if m:
        title = re.sub(r"<[^>]+>", " ", m.group(1))
        title = re.sub(r"\s+", " ", title).strip()

    # Date: try multiple patterns
    date = ""
    for pat in [
        r'datetime="(\d{4}-\d{2}-\d{2})',
        r"Release Date[:\s]*</?\w+>\s*(\d{1,2}/\d{1,2}/\d{4})",
        r'<meta[^>]*name="dcterms.date"[^>]*content="(\d{4}-\d{2}-\d{2})',
    ]:
        mm = re.search(pat, html)
        if mm:
            date = mm.group(1)
            break

    # Programs: look in body for bracketed program codes
    programs = re.findall(
        r"\b(IRAN|IRGC|IFSR|SDGT|RUSSIA[-A-Z0-9]*|DPRK[-A-Z0-9]*|NKIR|CYBER2|TCO|NARCO|"
        r"GLOMAG|HRIT|VENEZUELA|NICARAGUA|SYRIA|UKRAINE|CUBA|BURMA|UKRAINE-EO13661|"
        r"BELARUS|SOMALIA|YEMEN|CAR|CONGO|LIBYA|SUDAN|ZIMBABWE|LEBANON)\b",
        html,
    )
    programs = list(dict.fromkeys(programs))  # dedup preserve order

    return title, programs, date


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--index-dir",
        type=Path,
        default=Path("data/labels_raw"),
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("data/labels_raw/ofac_action_pages"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/labels_raw/ofac_press_releases_parsed.json"),
    )
    parser.add_argument(
        "--max-actions",
        type=int,
        default=0,
        help="Limit number of action pages (0 = all)",
    )
    args = parser.parse_args()

    links = extract_action_links(args.index_dir)
    print(f"Found {len(links)} unique action links from index HTML", flush=True)

    if args.max_actions > 0:
        links = links[: args.max_actions]

    records = []
    n_fetched = 0
    n_addrs = 0
    chain_counts: dict[str, int] = {}

    print(f"Fetching {len(links)} action pages (concurrent, 4 workers)...", flush=True)
    html_map = fetch_action_page_concurrent(links, args.cache_dir, max_workers=4)
    print(f"Fetched: {len(html_map)} / {len(links)}", flush=True)

    for i, link in enumerate(links):
        html = html_map.get(link)
        if not html:
            continue
        n_fetched += 1
        title, programs, date = extract_entity_and_program(html)
        action_date = action_date_from_link(link, date)
        if action_date and action_date < FIRST_CRYPTO_ACTION_DATE:
            # no digital-currency designation existed before 2018-11-28: whatever matched an
            # address shape on this page is a base64 fragment, not an address (MEDIUM-2)
            print(
                f"ERROR parse_ofac_press_releases: page {link} dated {action_date} predates the "
                f"first OFAC digital-currency designation — skipped",
                file=sys.stderr,
            )
            continue
        addrs_with_actions = extract_address_actions(html)
        if not addrs_with_actions:
            continue
        source_url = f"https://ofac.treasury.gov{link}"
        sanctions_ref = "; ".join(["OFAC"] + programs) if programs else "OFAC"

        for addr, chains in sorted(addrs_with_actions.items()):
            for chain, rec in sorted(
                press_release_records(
                    addr,
                    chains,
                    title=title,
                    source_url=source_url,
                    link=link,
                    action_date=action_date,
                    page_date=date,
                    programs=programs,
                    sanctions_ref=sanctions_ref,
                )
            ):
                records.append(rec)
                chain_counts[chain] = chain_counts.get(chain, 0) + 1
                n_addrs += 1

        if (i + 1) % 20 == 0:
            print(f"  [{i+1}/{len(links)}] fetched={n_fetched} addrs={n_addrs}", flush=True)

    print(f"\nFetched {n_fetched} action pages, emitted {len(records)} records")
    print(f"By chain: {sorted(chain_counts.items(), key=lambda x: -x[1])}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, ensure_ascii=False, separators=(",", ":"))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
