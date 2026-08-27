#!/usr/bin/env python3
"""Find privacy-protocol addresses that the mixer registry does not carry.

Context. The bridge-registry build classified every L2BEAT project and set aside the
ones that are not bridges. Among those set-aside rows are privacy protocols — which are
exactly what the mixer registry is for, and which it does not contain. This script
establishes the delta; it does NOT label anything.

The distinction matters: L2BEAT's classification is a LEAD, not a label. An
address found here is a candidate to attribute FROM THE CHAIN yourself. Importing
someone else's label string would make you a label-database consumer and would
poison a training pool with third-party attribution.

Output is therefore named `candidates`, never `labels`.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from collections import Counter
from pathlib import Path

# Kinds that describe a privacy system rather than a bridge. Matched case-insensitively
# against project_kind and project_declared_type; both are L2BEAT's own vocabulary.
PRIVACY_TOKENS = ("privacy", "mixer", "tumbler", "shielded", "anonym")


def _fetch(uri: str, dest: Path) -> None:
    """Stage an input locally: s3:// URIs via the aws CLI, else a local copy."""
    if dest.exists():
        return
    if uri.startswith("s3://"):
        r = subprocess.run(["aws", "s3", "cp", uri, str(dest), "--quiet"],
                           check=False, capture_output=True, text=True, timeout=900)
        if r.returncode != 0:
            raise subprocess.CalledProcessError(r.returncode, ["aws", "s3", "cp", uri],
                                                output=r.stdout, stderr=(r.stderr or "")[:8000])
    else:
        shutil.copyfile(uri, dest)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--excluded", required=True,
                    help="excluded_non_bridge.parquet from build_bridge_registry (path or s3:// URI)")
    ap.add_argument("--mixer", required=True,
                    help="mixer registry.parquet from build_mixer_registry (path or s3:// URI)")
    ap.add_argument("--workdir", default="out/labels")
    ap.add_argument("--out", default="out/labels/mixer_delta_candidates.json")
    args = ap.parse_args()

    import pyarrow.parquet as pq

    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)
    exc_path, mix_path = work / "excluded.parquet", work / "mixer.parquet"
    _fetch(args.excluded, exc_path)
    _fetch(args.mixer, mix_path)

    exc = pq.read_table(exc_path).to_pylist()
    mix_tbl = pq.read_table(mix_path)
    mix = mix_tbl.to_pylist()

    print(f"excluded_non_bridge rows : {len(exc)}")
    print(f"mixer registry rows      : {len(mix)}")
    print(f"mixer registry columns   : {mix_tbl.schema.names}")
    print("\nproject_kind in excluded_non_bridge:")
    for kind, n in Counter(r.get("project_kind") for r in exc).most_common():
        print(f"  {str(kind):32s} {n}")
    print("\nproject_declared_type in excluded_non_bridge:")
    for kind, n in Counter(r.get("project_declared_type") for r in exc).most_common():
        print(f"  {str(kind):32s} {n}")

    # Which column in the mixer registry holds the address? Detect rather than assume.
    addr_col = next((c for c in mix_tbl.schema.names
                     if "address" in c.lower() or c.lower() in ("addr", "hex")), None)
    if addr_col is None:
        raise SystemExit(f"no address-like column in the mixer registry: {mix_tbl.schema.names}")
    known = {str(r[addr_col]).lower() for r in mix if r.get(addr_col)}
    print(f"\nmixer address column     : {addr_col}  ({len(known)} distinct)")

    def is_privacy(row: dict) -> bool:
        blob = " ".join(str(row.get(k, "")) for k in
                        ("project_kind", "project_declared_type", "bridge")).lower()
        return any(tok in blob for tok in PRIVACY_TOKENS)

    privacy_rows = [r for r in exc if is_privacy(r)]
    print(f"\nprivacy-flavoured rows   : {len(privacy_rows)}")

    candidates = []
    for r in privacy_rows:
        addr = (r.get("escrow_address") or r.get("escrow_address_raw") or "").lower()
        if not addr:
            continue
        candidates.append({
            "address": addr,
            "chain": r.get("chain"),
            "lead_project": r.get("bridge"),
            "lead_kind": r.get("project_kind"),
            "lead_declared_type": r.get("project_declared_type"),
            "lead_source_repo": r.get("source_repo"),
            "lead_source_commit": r.get("source_commit"),
            "already_in_mixer_registry": addr in known,
            "attribution": None,
            "attribution_basis": (
                "PENDING — must be derived from first-party/on-chain evidence. "
                "The lead_* fields are L2BEAT's classification and are recorded as a LEAD "
                "only; importing them as the label is banned."
            ),
        })

    missing = [c for c in candidates if not c["already_in_mixer_registry"]]
    print(f"privacy addresses        : {len(candidates)}")
    print(f"  already in registry    : {len(candidates) - len(missing)}")
    print(f"  ABSENT from registry   : {len(missing)}")
    for c in missing:
        print(f"    {c['chain']:10s} {c['address']}  <- {c['lead_project']} "
              f"({c['lead_kind']}/{c['lead_declared_type']})")

    payload = {
        "excluded_rows": len(exc),
        "mixer_rows": len(mix),
        "mixer_address_column": addr_col,
        "privacy_candidates": len(candidates),
        "absent_from_registry": len(missing),
        "candidates": candidates,
        "note": "candidates, not labels — attribution is still PENDING for every row",
    }
    Path(args.out).write_text(json.dumps(payload, indent=2))
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
