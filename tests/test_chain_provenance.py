"""Contract P (2026-09-14): a label's chain is a claim of its source, never a default.

- chains.normalize_chain: one spelling per chain at ingest (xdai → gnosis, Avax →
  avalanche_c); merge_to_unified applies it to records and labels.
- parse_ofac_press_releases: the ticker OFAC prints next to an address decides the
  chain (one address under ETH, ARB and BSC → three chains); token tickers by
  address shape; an address OFAC mentions without a ticker keeps the shape
  fallback, marked chain_evidence="shape".
- parse_crypto_rekts: one record per declared EVM chain; no declared EVM chain →
  "evm", not "ethereum"; Avax → avalanche_c; a Tron T-address stays tron.
Addresses are synthetic or public OFAC rows; no label is attached to a real party
beyond what OFAC published.
"""

from __future__ import annotations

import json
from pathlib import Path

from openlabels.chains import EVM_CHAINS, normalize_chain
from openlabels.pipelines.merge_to_unified import main as merge_main
from openlabels.pipelines.parse_crypto_rekts import parse_one
from openlabels.pipelines.parse_ofac_press_releases import extract_addresses_with_evidence

SIM = "0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c"  # SDN row listed under ETH, ARB and BSC
EVM_A = "0x" + "11" * 20
EVM_B = "0x" + "22" * 20
TRON_T = "TNiq9AXBp9EjUqhDhrwrfvAA8U3GUQZH81"  # public SDN row (format only)


def test_normalize_chain_aliases() -> None:
    assert normalize_chain("xdai") == "gnosis"
    assert normalize_chain(" Avax ") == "avalanche_c"
    assert normalize_chain("ETH") == "ethereum"
    assert normalize_chain("base") == "base"
    assert normalize_chain(None) == ""
    assert "evm" in EVM_CHAINS and "tron" not in EVM_CHAINS


def test_press_release_chain_from_ticker() -> None:
    html = (
        f"<p>Digital Currency Address - ETH {SIM}; alt. Digital Currency Address - ARB {SIM}; "
        f"alt. Digital Currency Address - BSC {SIM}; Digital Currency Address - USDC {EVM_A}; "
        f"also mentioned in prose: {EVM_B} and Digital Currency Address - TRX {TRON_T}.</p>"
    )
    out = extract_addresses_with_evidence(html)
    assert out[SIM] == {("ethereum", "ticker"), ("arbitrum", "ticker"), ("bsc", "ticker")}
    assert out[EVM_A] == {("ethereum", "ticker")}  # USDC on a 0x address → ethereum by shape
    assert out[EVM_B] == {("ethereum", "shape")}  # no ticker → old fallback, marked as such
    assert out[TRON_T] == {("tron", "ticker")}


def _rekt(networks: list[str], addresses: list[str], name: str = "Example Rug") -> dict:
    return {
        "id": 1,
        "project_name": name,
        "scam_type": {"type": "Rugpull"},
        "scamNetworks": [{"networks": {"name": n}} for n in networks],
        "token_address": addresses[0],
        "token_addresses": [{"address": a} for a in addresses[1:]],
        "description": "",
    }


def test_rekt_no_declared_evm_chain_is_evm_not_ethereum() -> None:
    recs = parse_one(_rekt(["Other"], [EVM_A]))
    assert [(r["address"], r["chain"]) for r in recs] == [(EVM_A, "evm")]
    recs = parse_one(_rekt(["Centralized"], [EVM_A]))
    assert recs[0]["chain"] == "evm"
    recs = parse_one(_rekt(["Solana"], [EVM_A]))  # a 0x address cannot be Solana
    assert recs[0]["chain"] == "evm"


def test_rekt_one_record_per_declared_evm_chain() -> None:
    recs = parse_one(_rekt(["Ethereum", "Optimism"], [EVM_A]))
    assert sorted(r["chain"] for r in recs) == ["ethereum", "optimism"]
    assert all(r["labels"][0]["chain"] == r["chain"] for r in recs)


def test_rekt_avax_and_tron() -> None:
    recs = parse_one(_rekt(["Avax"], [EVM_A]))
    assert recs[0]["chain"] == "avalanche_c"
    recs = parse_one(_rekt(["TRON"], [TRON_T]))
    assert recs[0]["chain"] == "tron"


def test_merge_normalises_chain_spellings(tmp_path: Path, monkeypatch) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "a.json").write_text(
        json.dumps(
            [
                {
                    "address": EVM_A,
                    "chain": "xdai",
                    "labels": [{"name": "Agave", "type": "other", "source": "dawsbot_eth_labels", "chain": "xdai"}],
                },
                {
                    "address": EVM_A,
                    "chain": "Gnosis",
                    "labels": [{"name": "Agave", "type": "other", "source": "crypto_rekts", "chain": "gnosis"}],
                },
            ]
        )
    )
    out = tmp_path / "unified.json"
    monkeypatch.setattr(
        "sys.argv",
        ["merge", "--raw-dir", str(raw), "--inputs", "a.json", "--output", str(out)],
    )
    merge_main()
    store = json.loads(out.read_text())
    rec = store[EVM_A]
    assert rec["chain"] == "gnosis"
    assert {lab["chain"] for lab in rec["labels"]} == {"gnosis"}
    assert len(rec["labels"]) == 2  # two sources, same chain, different source → both kept
