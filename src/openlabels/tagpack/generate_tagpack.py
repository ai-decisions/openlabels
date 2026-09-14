"""TagPack generator over unified labels.

Emits a GraphSense-style TagPack YAML from a unified label store with a
per-row `source` URI. NO external submission happens here — output is a
local file, validated locally.

Provenance discipline: the per-source URIs below are taken from the harvest
code that BUILT each source, not invented. A source key with no authentic
URI keeps a `provenance:` note instead of a fabricated link, and — because
the GraphSense schema REQUIRES `source` per tag — such rows are emitted only
when `--allow-unsourced` is passed, otherwise skipped and counted. Honest
gap, not decoration.

LICENCE FILTER: rows whose label source is a non-redistributable dataset
(OpenSanctions CC-BY-NC; Dune Spellbook BSL 1.1) are EXCLUDED by default
(`--exclude-sources`) — a public TagPack must not carry NC/BSL-derived rows.

Actor/label semantics: one tag per (address, chain, label-name). `category` maps
our label types onto the GraphSense concept taxonomy where the mapping is clean;
unmappable types ride through as `abuse` only when genuinely abusive, else the
tag carries no concept (allowed by schema).

One tag per label CHAIN: a record's labels may sit on two chains when the same
20-byte payload is an EVM address and a Tron address (the store keys both under
one hex); each label's chain decides the tag's currency and address form.

Confidence and actors: every tag gets a GraphSense confidence level from its
label source (SOURCE_CONFIDENCE; a source not in the table is emitted as the
explicit taxonomy floor `unknown`), hoisted to the header when the whole pack
is one level; an entity that exists in the GraphSense actorpack carries
`actor` (ACTOR_BY_LABEL). Both were absent from the pack reviewed in
graphsense/graphsense-tagpacks#53 (2026-09-14) and the local validator below
now refuses a pack without them or with a Tron address under another currency.

Usage:
    python3 -m openlabels.tagpack.generate_tagpack --labels unified_labels.json \
        --out tagpack.yaml --min-rows 100
    python3 -m openlabels.tagpack.generate_tagpack --validate tagpack.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from openlabels.tron_address import hex_to_base58check, is_base58check

# Authentic per-source provenance (from the harvest code, see module docstring).
SOURCE_URI: dict[str, str] = {
    "ofac": "https://www.treasury.gov/ofac/downloads/sdn.csv",
    "ofac_sdn": "https://www.treasury.gov/ofac/downloads/sdn.csv",
    "ofac_press_release": "https://home.treasury.gov/policy-issues/financial-sanctions/recent-actions",
    "opensanctions": "https://data.opensanctions.org/datasets/",
    "walletexplorer": "https://www.walletexplorer.com/",
    "dawsbot_eth_labels": "https://github.com/dawsbot/eth-labels",
    "dawsbot_tokens": "https://github.com/dawsbot/eth-labels",
    "virtuals": "https://api.virtuals.io/api/virtuals",
    "virtuals_bridge": "https://api.virtuals.io/api/virtuals",
    "crypto_rekts": "https://rekt.news/",
    "tronscan_public": "https://apilist.tronscanapi.com",
    "flashbots": "https://github.com/flashbots/mev-inspect-py",
    "mev_inspect": "https://github.com/flashbots/mev-inspect-py",
    "tornado_interactors": "https://github.com/tornadocash",
}
# Curated in-repo lists: real provenance is this repository, not an external URL.
REPO_URI = "https://github.com/ai-decisions/openlabels"
SOURCE_URI["known_exchanges"] = REPO_URI
SOURCE_URI["known_mixers"] = REPO_URI
SOURCE_URI["ethereum_agents_curated"] = REPO_URI

# GraphSense confidence taxonomy (tagpack-tool src/tagpack/db/confidence.csv), per
# label source. OFAC is a public authority → `authority_data`, the level the
# repository's own OFAC-derived packs carry (hydra.yaml, blender_io.yaml,
# lazarus.yaml). A source not listed here is emitted as the taxonomy floor
# `unknown` EXPLICITLY — the consumer would otherwise assign it silently.
SOURCE_CONFIDENCE: dict[str, str] = {
    "ofac": "authority_data",
    "ofac_sdn": "authority_data",
    "ofac_press_release": "authority_data",
}
CONFIDENCE_FLOOR = "unknown"
CONFIDENCE_LEVELS = frozenset({
    "override", "ownership", "ledger_immanent", "manual_transaction", "service_api",
    "forensic_investigation", "authority_data", "trusted_provider", "service_data",
    "forensic", "untrusted_transaction", "web_crawl", "heuristic", "unknown",
})

# OFAC entity name (= the tag label) → GraphSense actor id. Only ids that exist in
# graphsense-tagpacks actors/graphsense.actorpack.yaml (verified 2026-09-14); an
# entity without an actor there carries no `actor` field rather than a guess.
ACTOR_BY_LABEL: dict[str, str] = {
    "HYDRA MARKET": "hydramarket",
    "BLENDER.IO": "blenderio",
    "GARANTEX EUROPE OU": "garantex",
    "CHATEX": "chatex",
    "LAZARUS GROUP": "lazarusgroup",
    "SINBAD": "sinbadio",
}

# Sources whose datasets are NOT redistributable (licence, not quality):
# OpenSanctions = CC-BY-NC 4.0; Dune Spellbook = BSL 1.1.
DEFAULT_EXCLUDED_SOURCES = ("opensanctions", "dune_spellbook")

# GraphSense tagpack currency codes; chains outside this set are skipped (counted).
CHAIN_TO_CURRENCY = {
    "bitcoin": "BTC",
    "ethereum": "ETH",
    "tron": "TRX",
    "litecoin": "LTC",
    "arbitrum": "ETH",  # L2 addresses are EVM/ETH-format; noted per-tag via context
    "base": "ETH",
    "optimism": "ETH",
}

# Our label types → GraphSense abuse/category concepts (only clean mappings).
TYPE_TO_CATEGORY = {
    "exchange": "exchange",
    "illicit": None,  # too coarse — no false precision
    "sanctioned": "sanction",
    "rugpull": "scam",
    "honeypot": "scam",
    "phishing": "phishing",
    "ai_agent": None,
    "licit": None,
    "other": None,
}


def build(
    labels_path: Path,
    out_path: Path,
    min_rows: int,
    allow_unsourced: bool,
    excluded_sources: tuple[str, ...] = DEFAULT_EXCLUDED_SOURCES,
    lastmod: str | None = None,
    title: str | None = None,
) -> dict:
    with labels_path.open() as f:
        data = json.load(f)

    tags: list[dict] = []
    # One tag per (address, currency, label, source). Two label chains that map to
    # the same GraphSense currency (ethereum + arbitrum → ETH; OFAC lists SIM Hyon
    # Sop's 0x4f47bc… under both) must not become two identical tags — the
    # official validator flags the duplicate. Such a tag lists every EVM chain the
    # address is labelled on in `context.chains`; a single L2 keeps `evm_chain`.
    seen_tag: dict[tuple, dict] = {}
    tag_chains: dict[tuple, list[str]] = {}
    skipped_chain: dict[str, int] = {}
    skipped_unsourced: dict[str, int] = {}
    skipped_licence: dict[str, int] = {}
    for addr, rec in data.items():
        rec_chain = rec.get("chain", "")
        for lbl in rec.get("labels", []):
            # The label's chain wins over the record's: the store is address-keyed,
            # and a Tron address whose 20-byte payload equals an EVM address shares
            # its key (GAZA NOW, SDN-47635) — the record says ethereum, the tron
            # label is the second chain and gets its own tag (2026-09-14).
            chain = lbl.get("chain") or rec_chain
            currency = CHAIN_TO_CURRENCY.get(chain)
            if currency is None:
                skipped_chain[chain] = skipped_chain.get(chain, 0) + 1
                continue
            src = lbl.get("source", "")
            if src in excluded_sources:
                skipped_licence[src] = skipped_licence.get(src, 0) + 1
                continue
            uri = SOURCE_URI.get(src)
            if uri is None and not allow_unsourced:
                skipped_unsourced[src] = skipped_unsourced.get(src, 0) + 1
                continue
            # The unified store keeps Tron in canonical 0x-hex (merge_to_unified
            # address policy); a public TagPack must carry the native base58check
            # T-form or the tags are dead for every GraphSense consumer.
            tag_addr = rec.get("address", addr)
            if chain == "tron" and len(tag_addr) == 42 and tag_addr.startswith("0x"):
                tag_addr = hex_to_base58check(tag_addr)
            # strip BEFORE truthiness: a whitespace-only name (" ") is truthy and
            # sailed through to a schema-invalid empty label (GraphSense validator
            # caught it 2026-07-25; the presence-only local check below did not).
            label = (lbl.get("name") or "").strip() or (lbl.get("type") or "").strip() or "unknown"
            source = uri or f"unverified:{src}"
            tkey = (tag_addr, currency, label, source)
            if tkey in seen_tag:
                if chain not in tag_chains[tkey]:
                    tag_chains[tkey].append(chain)
                continue
            tag = {
                "address": tag_addr,
                "currency": currency,
                "label": label,
                "source": source,
            }
            cat = TYPE_TO_CATEGORY.get(lbl.get("type", ""))
            if cat:
                tag["category"] = cat
            tag["confidence"] = SOURCE_CONFIDENCE.get(src, CONFIDENCE_FLOOR)
            actor = ACTOR_BY_LABEL.get(label)
            if actor:
                tag["actor"] = actor
            seen_tag[tkey] = tag
            tag_chains[tkey] = [chain]
            tags.append(tag)

    for tkey, chains in tag_chains.items():
        tag = seen_tag[tkey]
        if len(chains) > 1:
            tag["context"] = json.dumps({"chains": sorted(chains)})
        elif chains[0] not in ("bitcoin", "ethereum", "tron", "litecoin"):
            tag["context"] = json.dumps({"evm_chain": chains[0]})

    if len(tags) < min_rows:
        raise SystemExit(f"FAIL: only {len(tags)} tags produced, floor is {min_rows}")

    # One confidence level across the pack → header field, inherited by every
    # tag (the form the repository's own OFAC packs use); mixed → stays per tag.
    levels = {t["confidence"] for t in tags}
    header_confidence = next(iter(levels)) if len(levels) == 1 else None
    if header_confidence is not None:
        for t in tags:
            del t["confidence"]

    doc: dict = {
        "title": title or "AI DECISIONS unified public-label TagPack",
        "creator": "AI DECISIONS (aidecisions.ai)",
        "description": (
            "Public-source address labels unified by the openlabels attribution "
            "pipeline. Every tag carries the URI of the public source it was "
            "harvested from."
        ),
        "lastmod": lastmod or date.today().isoformat(),
    }
    if header_confidence is not None:
        doc["confidence"] = header_confidence
    doc["tags"] = tags

    # Emit YAML by hand-serialisation via json→yaml-safe scalars to avoid a hard
    # pyyaml dependency ordering issue on the box; pyyaml is used for -m validate.
    import yaml

    with out_path.open("w") as f:
        yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True, width=200)

    stats = {
        "tags": len(tags),
        "addresses": len({t["address"] for t in tags}),
        "currencies": sorted({t["currency"] for t in tags}),
        "confidence": header_confidence or "per-tag",
        "actors": sum(1 for t in tags if "actor" in t),
        "skipped_chains": skipped_chain,
        "skipped_unsourced": skipped_unsourced,
        "skipped_licence_excluded": skipped_licence,
    }
    print(json.dumps(stats, indent=2))
    return stats


def validate(path: Path) -> bool:
    """Local schema validation: required fields + types, GraphSense tagpack shape.

    Mirrors the mandatory-field rules of the GraphSense tagpack schema
    (title, creator, tags[]; per-tag address+currency+label+source, lastmod
    tag-or-header) and refuses the three defects the GraphSense maintainers
    found in graphsense-tagpacks#53 (2026-09-14): no confidence level (tag or
    header) — the official tool only WARNS and ingests as `unknown`; a
    confidence outside the taxonomy; a Tron base58check address under any
    currency but TRX, or a TRX tag in 0x-hex — dead tags either way. Run the
    official `tagpack-tool tagpack validate` before any external submission
    and READ ITS WARNINGS — this local check is a pre-flight, not a substitute.
    """
    import yaml

    with path.open() as f:
        doc = yaml.safe_load(f)
    errors: list[str] = []
    for field in ("title", "creator", "tags"):
        if field not in doc:
            errors.append(f"missing header field: {field}")
    if "lastmod" not in doc:
        errors.append("missing lastmod (required here at header level)")
    tags = doc.get("tags", [])
    if not isinstance(tags, list) or not tags:
        errors.append("tags must be a non-empty list")
    header_conf = doc.get("confidence")
    if header_conf is not None and header_conf not in CONFIDENCE_LEVELS:
        errors.append(f"header confidence {header_conf!r} not in the GraphSense taxonomy")
    for i, t in enumerate(tags):
        for field in ("address", "currency", "label", "source"):
            if not str(t.get(field, "") or "").strip():
                errors.append(f"tag[{i}] missing/blank {field}")
                break
        conf = t.get("confidence", header_conf)
        if conf is None:
            errors.append(f"tag[{i}] no confidence (tag or header) — ingested as 'unknown'")
        elif conf not in CONFIDENCE_LEVELS:
            errors.append(f"tag[{i}] confidence {conf!r} not in the GraphSense taxonomy")
        addr = str(t.get("address", "") or "")
        cur = t.get("currency")
        if is_base58check(addr) and cur != "TRX":
            errors.append(f"tag[{i}] Tron base58check address under currency {cur!r} — dead tag")
        elif cur == "TRX" and addr.startswith("0x"):
            errors.append(f"tag[{i}] TRX address in 0x-hex — dead tag, needs base58check")
        if len(errors) > 20:
            break
    if errors:
        print("VALIDATE FAIL:")
        for e in errors[:20]:
            print("  -", e)
        return False
    print(f"VALIDATE PASS: {len(tags)} tags, header complete")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--min-rows", type=int, default=100)
    ap.add_argument("--allow-unsourced", action="store_true")
    ap.add_argument(
        "--exclude-sources", default=",".join(DEFAULT_EXCLUDED_SOURCES),
        help="comma-separated label sources excluded on licence grounds "
             "(default: non-redistributable NC/BSL datasets)",
    )
    ap.add_argument(
        "--lastmod", default=None,
        help="override the lastmod date (YYYY-MM-DD) for reproducible builds",
    )
    ap.add_argument(
        "--title", default=None,
        help="override the pack title (e.g. for a single-source pack)",
    )
    ap.add_argument("--validate", type=Path, help="validate an existing tagpack")
    args = ap.parse_args()

    if args.validate:
        return 0 if validate(args.validate) else 1
    if not (args.labels and args.out):
        ap.error("--labels and --out required to generate")
    excluded = tuple(s.strip() for s in args.exclude_sources.split(",") if s.strip())
    build(args.labels, args.out, args.min_rows, args.allow_unsourced,
          excluded_sources=excluded, lastmod=args.lastmod, title=args.title)
    return 0 if validate(args.out) else 1


if __name__ == "__main__":
    sys.exit(main())
