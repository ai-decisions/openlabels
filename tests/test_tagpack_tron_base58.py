"""A public TagPack must carry Tron addresses in native base58check T-form.

The unified store keeps Tron in canonical 0x-hex (merge_to_unified address
policy); the generator converts back on emission — hex tags are dead for
every GraphSense consumer.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from openlabels.tagpack.generate_tagpack import build
from openlabels.tron_address import hex_to_base58check

HEX_ADDR = "0x" + "11" * 20


def _store(tmp_path: Path) -> Path:
    store = {
        HEX_ADDR: {
            "address": HEX_ADDR,
            "chain": "tron",
            "labels": [
                {"name": "Example Sanctioned", "type": "sanctioned",
                 "source": "ofac_sdn", "chain": "tron"}
            ],
        }
    }
    p = tmp_path / "unified.json"
    p.write_text(json.dumps(store))
    return p


def test_tron_tag_emitted_as_base58check(tmp_path: Path) -> None:
    out = tmp_path / "pack.yaml"
    build(_store(tmp_path), out, min_rows=1, allow_unsourced=False,
          lastmod="2026-01-01")
    doc = yaml.safe_load(out.read_text())
    (tag,) = doc["tags"]
    assert tag["currency"] == "TRX"
    assert tag["address"] == hex_to_base58check(HEX_ADDR)
    assert tag["address"].startswith("T")
    assert "0x" not in tag["address"]


def test_title_override(tmp_path: Path) -> None:
    out = tmp_path / "pack.yaml"
    build(_store(tmp_path), out, min_rows=1, allow_unsourced=False,
          lastmod="2026-01-01", title="AI DECISIONS — OFAC SDN crypto addresses")
    doc = yaml.safe_load(out.read_text())
    assert doc["title"] == "AI DECISIONS — OFAC SDN crypto addresses"
