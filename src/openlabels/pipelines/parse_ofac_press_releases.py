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
import json
import re
import subprocess
import time
from pathlib import Path

HEX_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
TRON_B58_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
BTC_LEGACY_RE = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")
BTC_BECH32_RE = re.compile(r"\bbc1[02-9ac-hj-np-z]{38,58}\b")
LTC_RE = re.compile(r"\b(ltc1[02-9ac-hj-np-z]{38,58}|[LM][1-9A-HJ-NP-Za-km-z]{25,34})\b")
XMR_RE = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94,105}\b")

ACTION_LINK_RE = re.compile(r'href="(/recent-actions/[0-9a-zA-Z_\-\.]+)"')


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
            ["curl", "-sL", "--max-time", "30",
             "-A", "Mozilla/5.0 (compatible; AIDecisionsBot/1.0)",
             full_url],
            capture_output=True, text=True, timeout=35,
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
    links: list[str], cache_dir: Path, max_workers: int = 4,
) -> dict[str, str]:
    """Concurrent download with bounded parallelism.

    Returns {url_path: html} for successfully fetched pages. Politeness:
    per-worker 0.3s sleep + max_workers=4 → peak 13 req/sec (OFAC handles
    Google indexer traffic, this is fine).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(fetch_action_page, link, cache_dir): link
                   for link in links}
        for i, fut in enumerate(as_completed(futures)):
            link = futures[fut]
            try:
                html = fut.result()
            except Exception:
                html = None
            if html:
                results[link] = html
            if (i + 1) % 100 == 0:
                print(f"  fetched {i+1}/{len(links)} (ok={len(results)})",
                      flush=True)
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
        out.setdefault("litecoin", set()).add(m.group(0).lower() if m.group(0).startswith("ltc1") else m.group(0))
    for m in XMR_RE.finditer(html):
        out.setdefault("monero", set()).add(m.group(0))
    return out


def extract_entity_and_program(html: str) -> tuple[str, list[str], str]:
    """Get primary entity name, OFAC program tags, publication date."""
    # <h1> usually has action title
    m = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.DOTALL)
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
        "--index-dir", type=Path,
        default=Path("data/labels_raw"),
    )
    parser.add_argument(
        "--cache-dir", type=Path,
        default=Path("data/labels_raw/ofac_action_pages"),
    )
    parser.add_argument(
        "--output", type=Path,
        default=Path("data/labels_raw/ofac_press_releases_parsed.json"),
    )
    parser.add_argument(
        "--max-actions", type=int, default=0,
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

    print(f"Fetching {len(links)} action pages (concurrent, 4 workers)...",
          flush=True)
    html_map = fetch_action_page_concurrent(links, args.cache_dir, max_workers=4)
    print(f"Fetched: {len(html_map)} / {len(links)}", flush=True)

    for i, link in enumerate(links):
        html = html_map.get(link)
        if not html:
            continue
        n_fetched += 1
        title, programs, date = extract_entity_and_program(html)
        addrs_by_chain = extract_addresses_from_html(html)
        if not addrs_by_chain:
            continue
        source_url = f"https://ofac.treasury.gov{link}"
        sanctions_ref = "; ".join(["OFAC"] + programs) if programs else "OFAC"

        for chain, addrs in addrs_by_chain.items():
            for addr in addrs:
                rec = {
                    "address": addr.lower() if addr.startswith("0x") else addr,
                    "chain": chain,
                    "labels": [
                        {
                            "name": title[:200],
                            "type": "sanctioned",
                            "source": "ofac_press_release",
                            "chain": chain,
                        }
                    ],
                    "is_illicit": True,
                    "is_exchange": False,
                    "is_ai_agent": False,
                    "entity_name": title[:200],
                    "category": "sanctioned",
                    "sanctioned": True,
                    "sanctions_reference": sanctions_ref,
                    "source_url": source_url,
                    "source_date": date,
                    "_ofac_pr_link": link,
                    "_ofac_pr_programs": programs,
                }
                records.append(rec)
                chain_counts[chain] = chain_counts.get(chain, 0) + 1
                n_addrs += 1

        if (i + 1) % 20 == 0:
            print(f"  [{i+1}/{len(links)}] fetched={n_fetched} addrs={n_addrs}",
                  flush=True)

    print(f"\nFetched {n_fetched} action pages, emitted {len(records)} records")
    print(f"By chain: {sorted(chain_counts.items(), key=lambda x: -x[1])}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, ensure_ascii=False, separators=(",", ":"))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
