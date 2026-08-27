#!/usr/bin/env python3
"""Bridge escrow registry from L2BEAT (public sources, $0).

Builds a registry of bridge escrow addresses (default quality gates:
>=150 addresses across >=9 bridges, fail-closed).

SOURCE CHOICE, measured 2026-07-27:
  * DefiLlama bridges API — DEAD as a free source: `https://bridges.llama.fi/bridges`
    returns HTTP 402 Payment Required.
  * Dune Spellbook dump — 5,053 rows, categories exchange/institution/infrastructure
    only; exactly ONE row mentions a bridge (HTX Bridge 1, an exchange-operated
    bridge). It is a CEX/VASP source, not a bridge source.
  * L2BEAT (github.com/l2beat/l2beat, MIT) — 264 project configs, and 191 of them carry a
    machine-readable `tvs.json` whose token entries hold TYPED escrow references:
        {"type": "balanceOfEscrow", "address": <token>, "chain": <chain>,
         "escrowAddress": "0x..."}
    This is the extraction target. Parsing the TypeScript instead would be wrong: the
    project .ts files also contain governance addresses inside Tally proposal URLs, so a
    blind /0x[0-9a-f]{40}/ sweep pollutes the registry with non-escrow contracts (measured
    on arbitrum.ts).

PROVENANCE: every row carries the L2BEAT commit sha the file was read at, the exact source
path, and the fetch timestamp. The commit is PINNED as an argument — a registry built from
"main at some point" is not reproducible.

Fail-closed: writes nothing unless the contract gates (>=150 addresses, >=9 bridges) are
evaluated and reported; the gate result is recorded in the manifest either way, and a FAIL
exits non-zero without uploading.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import UTC, datetime

import pyarrow as pa
import pyarrow.parquet as pq

REPO = "l2beat/l2beat"
UA = {"User-Agent": "ai-decisions-research/1.0"}
MIN_ADDRESSES = 150
MIN_BRIDGES = 9


def log(msg: str) -> None:
    print(f"{datetime.now(UTC).isoformat(timespec='seconds')} {msg}", flush=True)


def fetch(url: str, tries: int = 4) -> bytes:
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503) and i < tries - 1:
                wait = 2 ** (i + 1)
                log(f"WARN {url.rsplit('/', 1)[-1]}: HTTP {e.code}, retry in {wait}s")
                time.sleep(wait)
                last = e
                continue
            raise
        except Exception as e:  # noqa: BLE001 — retried, re-raised below
            last = e
            time.sleep(2 ** (i + 1))
    raise RuntimeError(f"fetch failed after {tries}: {url}: {last}")


def resolve_sha(ref: str) -> tuple[str, str]:
    d = json.loads(fetch(f"https://api.github.com/repos/{REPO}/commits/{ref}"))
    return d["sha"], d["commit"]["committer"]["date"]


def list_tvs_paths(sha: str) -> list[str]:
    tree = json.loads(fetch(f"https://api.github.com/repos/{REPO}/git/trees/{sha}?recursive=1"))
    if tree.get("truncated"):
        raise RuntimeError("git tree truncated — cannot enumerate exhaustively; abort")
    return sorted(
        t["path"]
        for t in tree["tree"]
        if t["type"] == "blob"
        and t["path"].startswith("packages/config/src/projects/")
        and t["path"].endswith("/tvs.json")
    )


def walk_escrows(node, out: list[dict]) -> None:
    """Collect every typed balanceOfEscrow reference, at any nesting depth."""
    if isinstance(node, dict):
        if node.get("type") == "balanceOfEscrow" and node.get("escrowAddress"):
            out.append(
                {
                    "escrow_address": node["escrowAddress"],
                    "chain": node.get("chain"),
                    "token_address": node.get("address"),
                }
            )
        for v in node.values():
            walk_escrows(v, out)
    elif isinstance(node, list):
        for v in node:
            walk_escrows(v, out)


def classify_project(sha: str, project_dir: str) -> dict:
    """L2BEAT project kind, read from the project's own .ts declaration.

    MANDATORY, not cosmetic: L2BEAT tracks privacy protocols alongside bridges. Measured
    2026-07-27 — `tornado-cash` (19 escrow addresses) and `privacy-pools` (13) sit in the
    same tvs.json corpus as `arbitrum` and `across`. Shipping them unfiltered gives 32
    MIXER addresses the label `edge_type=bridge` in a downstream merge; 19 of those 32
    were already in a mixer registry when measured. The distinction lives in the type system:
      ScalingProject                          -> L2 with canonical bridge escrows
      BaseProject + type:'intent'|'liquidity' -> bridge protocol
      BaseProject + ProjectPrivacyToken /
                    type:'denomination'       -> PRIVACY protocol, NOT a bridge
    """
    name = project_dir.rsplit("/", 1)[-1]
    try:
        src = fetch(
            f"https://raw.githubusercontent.com/{REPO}/{sha}/{project_dir}/{name}.ts"
        ).decode()
    except Exception:  # noqa: BLE001 — unknown kind is fail-closed below, never assumed bridge
        return {"kind": "unknown", "declared": None, "privacy_marker": False}
    scaling = "ScalingProject" in src
    privacy = "ProjectPrivacyToken" in src or "privacy" in src.lower().split("import")[0]
    declared = None
    for marker in ("denomination", "intent", "liquidity", "canonical", "aggregator"):
        if f"type: '{marker}'" in src:
            declared = marker
            break
    if privacy or declared == "denomination":
        kind = "privacy"
    elif scaling:
        kind = "scaling_l2"
    elif declared in ("intent", "liquidity", "canonical", "aggregator"):
        kind = "bridge"
    else:
        kind = "unknown"
    return {"kind": kind, "declared": declared, "privacy_marker": privacy}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ref", default="main", help="branch/tag/sha to pin (resolved to a sha)")
    ap.add_argument("--local-dir", default="out/bridge_registry")
    args = ap.parse_args()

    sha, committed = resolve_sha(args.ref)
    log(f"L2BEAT pinned at {sha} (committed {committed})")
    paths = list_tvs_paths(sha)
    log(f"tvs.json files: {len(paths)}")

    rows: list[dict] = []
    per_project: dict[str, set] = defaultdict(set)
    failed: list[str] = []
    fetched_at = datetime.now(UTC).isoformat(timespec="seconds")

    for i, p in enumerate(paths, 1):
        url = f"https://raw.githubusercontent.com/{REPO}/{sha}/{p}"
        try:
            doc = json.loads(fetch(url))
        except Exception as e:  # noqa: BLE001 — recorded, not silently dropped
            failed.append(f"{p}: {type(e).__name__}")
            log(f"CRITICAL {p}: {str(e)[:160]}")
            continue
        project = doc.get("projectId") or p.split("/")[-2]
        cls = classify_project(sha, p.rsplit("/", 1)[0])
        found: list[dict] = []
        walk_escrows(doc, found)
        for f in found:
            key = (f["escrow_address"].lower(), f["chain"] or "")
            per_project[project].add(key)
            rows.append(
                {
                    "bridge": project,
                    "project_kind": cls["kind"],
                    "project_declared_type": cls["declared"],
                    "escrow_address": f["escrow_address"].lower(),
                    "escrow_address_raw": f["escrow_address"],
                    "chain": f["chain"],
                    "token_address": (f["token_address"] or "").lower() or None,
                    "source_repo": REPO,
                    "source_commit": sha,
                    "source_path": p,
                    "fetched_at_utc": fetched_at,
                }
            )
        if i % 25 == 0:
            log(f"  {i}/{len(paths)} projects, {len(rows):,} escrow refs so far")

    if failed:
        log(f"CRITICAL: {len(failed)} project files unreadable — registry would be partial")
        for f in failed[:10]:
            log(f"   {f}")
        return 3

    # dedup to the registry grain: (bridge, escrow_address, chain)
    seen = set()
    uniq: list[dict] = []
    for r in rows:
        k = (r["bridge"], r["escrow_address"], r["chain"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)

    # SPLIT BY KIND — the bridge registry contains ONLY bridge-semantics escrows.
    # Privacy-protocol rows are kept in a separate file, never silently dropped and never
    # merged into the bridge surface (they would become edge_type=bridge on mixer addresses).
    bridge_rows = [r for r in uniq if r["project_kind"] in ("scaling_l2", "bridge")]
    privacy_rows = [r for r in uniq if r["project_kind"] == "privacy"]
    unknown_rows = [r for r in uniq if r["project_kind"] == "unknown"]

    addresses = {(r["escrow_address"], r["chain"]) for r in bridge_rows}
    bridges = {r["bridge"] for r in bridge_rows}
    gate_addr = len(addresses) >= MIN_ADDRESSES
    gate_bridge = len(bridges) >= MIN_BRIDGES

    log("=" * 66)
    log(f"escrow references (raw)      : {len(rows):,}")
    log(f"registry rows (deduped)      : {len(uniq):,}")
    log(
        f"  by kind                    : bridge-semantics {len(bridge_rows):,} / "
        f"privacy {len(privacy_rows):,} / unknown {len(unknown_rows):,} "
        f"(unknown is EXCLUDED from the registry — fail-closed)"
    )
    if privacy_rows:
        pnames = sorted({r["bridge"] for r in privacy_rows})
        n_priv = len({r["escrow_address"] for r in privacy_rows})
        log(f"  privacy protocols excluded : {pnames} — {n_priv} addresses")
    log(
        f"distinct (address, chain)    : {len(addresses):,}   gate >= {MIN_ADDRESSES}: "
        f"{'PASS' if gate_addr else 'FAIL'}"
    )
    log(
        f"distinct bridges             : {len(bridges):,}   gate >= {MIN_BRIDGES}: "
        f"{'PASS' if gate_bridge else 'FAIL'}"
    )
    chains = defaultdict(int)
    for r in bridge_rows:
        chains[r["chain"]] += 1
    log(f"chains                       : {dict(sorted(chains.items(), key=lambda x: -x[1])[:12])}")
    top = sorted(((len(v), k) for k, v in per_project.items()), reverse=True)[:12]
    log(f"top bridges by escrow count  : {[(k, n) for n, k in top]}")
    log("=" * 66)

    manifest = {
        "registry": "bridge_registry_v1",
        "built_at_utc": fetched_at,
        "source": {
            "repo": REPO,
            "commit": sha,
            "commit_date": committed,
            "license": "MIT",
            "files_read": len(paths),
            "extraction": "typed balanceOfEscrow.escrowAddress from tvs.json (no TS parsing)",
        },
        "rejected_sources": {
            "defillama_bridges_api": "HTTP 402 Payment Required (measured 2026-07-27)",
            "dune_spellbook_dump": "CEX/VASP slice; 1 of 5,053 rows bridge-related",
        },
        "counts": {
            "escrow_refs_raw": len(rows),
            "rows_deduped_all_kinds": len(uniq),
            "registry_rows_bridge_semantics": len(bridge_rows),
            "rows_privacy_excluded": len(privacy_rows),
            "rows_unknown_excluded": len(unknown_rows),
            "distinct_address_chain": len(addresses),
            "distinct_bridges": len(bridges),
        },
        "kind_filter": {
            "why": "L2BEAT tracks privacy protocols in the same corpus as bridges; unfiltered "
            "they would carry edge_type=bridge on mixer addresses in a downstream merge",
            "included_kinds": ["scaling_l2", "bridge"],
            "excluded_privacy_projects": sorted({r["bridge"] for r in privacy_rows}),
            "excluded_unknown_projects": sorted({r["bridge"] for r in unknown_rows}),
        },
        "gates": {
            "min_addresses": MIN_ADDRESSES,
            "min_bridges": MIN_BRIDGES,
            "addresses_pass": gate_addr,
            "bridges_pass": gate_bridge,
        },
    }

    import os

    os.makedirs(args.local_dir, exist_ok=True)
    ppath = os.path.join(args.local_dir, "bridge_escrows.parquet")
    pq.write_table(pa.Table.from_pylist(bridge_rows), ppath, compression="snappy")
    outs = [ppath]
    if privacy_rows or unknown_rows:
        # kept, not dropped: privacy rows are a cross-check against the mixer registry,
        # unknown rows are the review queue for the next classification pass
        opath = os.path.join(args.local_dir, "excluded_non_bridge.parquet")
        pq.write_table(
            pa.Table.from_pylist(privacy_rows + unknown_rows), opath, compression="snappy"
        )
        outs.append(opath)
    mpath = os.path.join(args.local_dir, "manifest.json")
    with open(mpath, "w") as fh:
        json.dump(manifest, fh, indent=1)
    outs.append(mpath)
    log(f"wrote {', '.join(f'{o} ({os.path.getsize(o):,} B)' for o in outs)}")

    if not (gate_addr and gate_bridge):
        log("GATE FAIL — the shortfall is the finding, not a reason to pad")
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
