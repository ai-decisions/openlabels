"""End-to-end determinism: the same fixed inputs must produce byte-identical
artefacts on every run (OFAC subset + raw sample → unified store → label set
parquet → TagPack YAML). This is the reproducibility gate: a clean clone
running this test twice, on any machine, prints the same sha256 values.

Inputs: a fixed public OFAC SDN subset (see tests/data/README.md for
provenance) plus synthetic fixtures (invented example entities and two
public infrastructure constants). No third-party dataset rows ship in this
repository.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from openlabels.ofac_attributed import parse_sdn_csv

DATA = Path(__file__).parent / "data"
RAW = DATA / "raw_sample.json"
BATCH = DATA / "batch_sample.jsonl"
OFAC_SUBSET = DATA / "ofac_sdn_subset.csv"
LASTMOD = "2026-01-01"


def _ofac_subset_as_raw_records() -> list[dict]:
    """The fixed public OFAC subset, converted to merge_to_unified raw shape."""
    records = []
    for a in parse_sdn_csv(OFAC_SUBSET):
        records.append(
            {
                "address": a.address,
                "chain": a.chain,
                "labels": [
                    {
                        "name": a.entity_name,
                        "type": "sanctioned",
                        "source": "ofac_sdn",
                        "chain": a.chain,
                    }
                ],
                "is_illicit": True,
                "is_exchange": False,
                "is_ai_agent": False,
                "entity_name": a.entity_name,
                "category": "sanctioned",
                "sanctioned": True,
                "sanctions_reference": f"OFAC SDN-{a.sdn_id}",
                "source_date": "2026-08-24",
            }
        )
    return records


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _run(args: list[str], cwd: Path) -> None:
    r = subprocess.run(
        [sys.executable, "-m", *args],
        cwd=cwd, capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0:
        raise AssertionError(
            f"{args[0]} rc={r.returncode}\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        )


def _build_once(work: Path) -> dict[str, str]:
    work.mkdir(parents=True, exist_ok=True)
    raw_dir = work / "raw"
    raw_dir.mkdir()
    (raw_dir / "raw_sample.json").write_bytes(RAW.read_bytes())
    (raw_dir / "ofac_subset.json").write_text(
        json.dumps(_ofac_subset_as_raw_records(), ensure_ascii=False)
    )

    store = work / "unified.json"
    _run(
        [
            "openlabels.pipelines.merge_to_unified",
            "--raw-dir", str(raw_dir),
            "--inputs", "ofac_subset.json", "raw_sample.json",
            "--output", str(store),
        ],
        cwd=work,
    )

    ls_out = work / "labelset"
    _run(
        [
            "openlabels.pipelines.build_label_set",
            "--batch", str(BATCH),
            "--batch-id", "repro-01",
            "--attributed-utc", "2026-01-01T00:00:00+00:00",
            "--out-dir", str(ls_out),
            "--execute",
        ],
        cwd=work,
    )

    tagpack = work / "tagpack.yaml"
    _run(
        [
            "openlabels.tagpack.generate_tagpack",
            "--labels", str(store),
            "--out", str(tagpack),
            "--min-rows", "1",
            "--lastmod", LASTMOD,
        ],
        cwd=work,
    )

    return {
        "unified_store": _sha(store),
        "label_set_parquet": _sha(ls_out / "label_set.parquet"),
        "tagpack": _sha(tagpack),
    }


def test_pipeline_byte_deterministic(tmp_path: Path) -> None:
    a = _build_once(tmp_path / "run_a")
    b = _build_once(tmp_path / "run_b")
    assert a == b, f"non-deterministic artefacts:\nA={a}\nB={b}"
    # Printed so two independent CI runs can be compared against each other.
    for name, sha in a.items():
        print(f"REPRO_SHA {name} {sha}")


def test_tagpack_excludes_nc_sources(tmp_path: Path) -> None:
    """The synthetic opensanctions-sourced row must be licence-filtered out."""
    shas = _build_once(tmp_path / "run")  # noqa: F841 — build side effect
    tagpack = (tmp_path / "run" / "tagpack.yaml").read_text()
    assert "NC Licensed Entity" not in tagpack
    assert "Example Exchange 1" in tagpack


def test_ofac_subset_parses() -> None:
    """The fixed public OFAC subset yields attributed records with entities."""
    records = _ofac_subset_as_raw_records()
    assert len(records) >= 8
    assert all(r["entity_name"] for r in records)
    assert all(r["sanctions_reference"].startswith("OFAC SDN-") for r in records)
