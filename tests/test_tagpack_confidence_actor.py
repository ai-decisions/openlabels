"""A public TagPack must carry a GraphSense confidence level and, where the
entity exists in the GraphSense actorpack, an actor — the two omissions the
maintainers asked us to fix in graphsense-tagpacks#53 (2026-09-14). The local
validator must refuse a pack that lacks them, and a Tron address under another
currency (the third finding). Addresses are synthetic (zero-byte payloads).
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from openlabels.tagpack.generate_tagpack import build, validate
from openlabels.tron_address import hex_to_base58check

TRON_ZERO_HEX = "0x" + "00" * 20
TRON_ZERO_T = hex_to_base58check(TRON_ZERO_HEX)
EVM_A = "0x" + "11" * 20
EVM_B = "0x" + "22" * 20


def _rec(addr: str, chain: str, name: str, source: str, ltype: str = "sanctioned") -> dict:
    return {
        "address": addr,
        "chain": chain,
        "labels": [{"name": name, "type": ltype, "source": source, "chain": chain}],
    }


def _write(tmp_path: Path, store: dict) -> Path:
    p = tmp_path / "unified.json"
    p.write_text(json.dumps(store))
    return p


def test_ofac_only_pack_hoists_authority_data_to_header(tmp_path: Path) -> None:
    store = {
        TRON_ZERO_HEX: _rec(TRON_ZERO_HEX, "tron", "HYDRA MARKET", "ofac_sdn"),
        EVM_A: _rec(EVM_A, "ethereum", "Example Sanctioned", "ofac_sdn"),
    }
    out = tmp_path / "pack.yaml"
    build(_write(tmp_path, store), out, min_rows=1, allow_unsourced=False, lastmod="2026-01-01")
    doc = yaml.safe_load(out.read_text())
    assert doc["confidence"] == "authority_data"
    assert all("confidence" not in t for t in doc["tags"])
    assert list(doc)[-1] == "tags"  # header fields first, tags last


def test_actor_only_for_entities_known_to_the_graphsense_actorpack(tmp_path: Path) -> None:
    store = {
        TRON_ZERO_HEX: _rec(TRON_ZERO_HEX, "tron", "HYDRA MARKET", "ofac_sdn"),
        EVM_A: _rec(EVM_A, "ethereum", "Example Sanctioned", "ofac_sdn"),
    }
    out = tmp_path / "pack.yaml"
    build(_write(tmp_path, store), out, min_rows=1, allow_unsourced=False, lastmod="2026-01-01")
    by_label = {t["label"]: t for t in yaml.safe_load(out.read_text())["tags"]}
    assert by_label["HYDRA MARKET"]["actor"] == "hydramarket"
    assert "actor" not in by_label["Example Sanctioned"]


def test_mixed_sources_keep_confidence_per_tag(tmp_path: Path) -> None:
    store = {
        EVM_A: _rec(EVM_A, "ethereum", "Example Sanctioned", "ofac_sdn"),
        EVM_B: _rec(EVM_B, "ethereum", "Example Exchange", "walletexplorer", "exchange"),
    }
    out = tmp_path / "pack.yaml"
    build(_write(tmp_path, store), out, min_rows=1, allow_unsourced=False, lastmod="2026-01-01")
    doc = yaml.safe_load(out.read_text())
    assert "confidence" not in doc
    conf = {t["label"]: t["confidence"] for t in doc["tags"]}
    assert conf == {"Example Sanctioned": "authority_data", "Example Exchange": "unknown"}
    assert validate(out)


def _pack(tmp_path: Path, header: dict, tags: list[dict]) -> Path:
    p = tmp_path / "hand.yaml"
    p.write_text(yaml.safe_dump({**header, "tags": tags}, sort_keys=False))
    return p


_HDR = {"title": "t", "creator": "c", "lastmod": "2026-01-01"}


def test_validate_refuses_pack_without_confidence(tmp_path: Path) -> None:
    ok = _pack(tmp_path, {**_HDR, "confidence": "authority_data"},
               [{"address": EVM_A, "currency": "ETH", "label": "x", "source": "s"}])
    assert validate(ok)
    missing = _pack(tmp_path, _HDR,
                    [{"address": EVM_A, "currency": "ETH", "label": "x", "source": "s"}])
    assert not validate(missing)
    bogus = _pack(tmp_path, {**_HDR, "confidence": "very_sure"},
                  [{"address": EVM_A, "currency": "ETH", "label": "x", "source": "s"}])
    assert not validate(bogus)


def test_validate_refuses_tron_address_under_other_currency(tmp_path: Path) -> None:
    dead = _pack(tmp_path, {**_HDR, "confidence": "authority_data"},
                 [{"address": TRON_ZERO_T, "currency": "BTC", "label": "x", "source": "s"}])
    assert not validate(dead)
    hex_trx = _pack(tmp_path, {**_HDR, "confidence": "authority_data"},
                    [{"address": TRON_ZERO_HEX, "currency": "TRX", "label": "x", "source": "s"}])
    assert not validate(hex_trx)
    live = _pack(tmp_path, {**_HDR, "confidence": "authority_data"},
                 [{"address": TRON_ZERO_T, "currency": "TRX", "label": "x", "source": "s"}])
    assert validate(live)
