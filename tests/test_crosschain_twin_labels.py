"""An address whose 20-byte payload is both an EVM address and a Tron address (OFAC
lists GAZA NOW, SDN-47635, that way) shares one hex key in the address-keyed store.
The merge must keep the label of each chain, and the TagPack must carry one tag per
label chain — the Tron tag in base58check of the same payload. Payload here is
synthetic (0x11…); the real case is documented in the contract."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from openlabels.pipelines.merge_to_unified import merge_label_entries, merge_records
from openlabels.tagpack.generate_tagpack import build
from openlabels.tron_address import hex_to_base58check

HEX = "0x" + "11" * 20


def _lbl(chain: str, name: str = "EXAMPLE TWIN", source: str = "ofac_sdn") -> dict:
    return {"name": name, "type": "sanctioned", "source": source, "chain": chain}


def test_same_name_and_source_on_two_chains_are_two_labels() -> None:
    out = merge_label_entries([_lbl("ethereum")], [_lbl("tron")])
    assert [x["chain"] for x in out] == ["ethereum", "tron"]


def test_same_chain_duplicate_is_still_dropped() -> None:
    out = merge_label_entries([_lbl("ethereum")], [_lbl("ethereum")])
    assert len(out) == 1


def test_merge_records_keeps_both_chains_in_labels() -> None:
    eth = {"address": HEX, "chain": "ethereum", "labels": [_lbl("ethereum")], "sanctioned": True}
    trx = {"address": HEX, "chain": "tron", "labels": [_lbl("tron")], "sanctioned": True}
    merged = merge_records(eth, trx)
    assert merged["chain"] == "ethereum"  # record chain: first wins, unchanged rule
    assert sorted(x["chain"] for x in merged["labels"]) == ["ethereum", "tron"]


def test_tagpack_emits_one_tag_per_label_chain(tmp_path: Path) -> None:
    store = {HEX: {"address": HEX, "chain": "ethereum", "labels": [_lbl("ethereum"), _lbl("tron")]}}
    (tmp_path / "unified.json").write_text(json.dumps(store))
    out = tmp_path / "pack.yaml"
    build(tmp_path / "unified.json", out, min_rows=1, allow_unsourced=False, lastmod="2026-01-01")
    tags = yaml.safe_load(out.read_text())["tags"]
    by_cur = {t["currency"]: t["address"] for t in tags}
    assert by_cur == {"ETH": HEX, "TRX": hex_to_base58check(HEX)}
    assert all(t["label"] == "EXAMPLE TWIN" for t in tags)


def test_two_evm_chains_of_one_currency_make_one_tag_with_chains_context(tmp_path: Path) -> None:
    store = {HEX: {"address": HEX, "chain": "ethereum", "labels": [_lbl("ethereum"), _lbl("arbitrum")]}}
    (tmp_path / "unified.json").write_text(json.dumps(store))
    out = tmp_path / "pack.yaml"
    build(tmp_path / "unified.json", out, min_rows=1, allow_unsourced=False, lastmod="2026-01-01")
    (tag,) = yaml.safe_load(out.read_text())["tags"]
    assert tag["currency"] == "ETH" and json.loads(tag["context"]) == {"chains": ["arbitrum", "ethereum"]}


def test_single_l2_label_keeps_evm_chain_context(tmp_path: Path) -> None:
    store = {HEX: {"address": HEX, "chain": "arbitrum", "labels": [_lbl("arbitrum")]}}
    (tmp_path / "unified.json").write_text(json.dumps(store))
    out = tmp_path / "pack.yaml"
    build(tmp_path / "unified.json", out, min_rows=1, allow_unsourced=False, lastmod="2026-01-01")
    (tag,) = yaml.safe_load(out.read_text())["tags"]
    assert json.loads(tag["context"]) == {"evm_chain": "arbitrum"}
