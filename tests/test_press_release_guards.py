"""Contract S (2026-09-14), S2 and S11 for the OFAC press-release and rekt parsers.

The retrospective review of contract P found the ticker regex capped at 90 characters:
a 95-character Monero address was cut and the cut string became a second, phantom
"sanctioned" address (7 on the cached pages). Now the token is read whole and must look
like an address of the inferred chain; an unknown ticker is never guessed by shape;
the <h1> search is skipped on a page without a closing tag; rekt network names are
matched case-insensitively. Addresses are synthetic."""

from __future__ import annotations

from openlabels.pipelines.parse_crypto_rekts import _network_chain
from openlabels.pipelines.parse_ofac_press_releases import (
    extract_addresses_with_evidence,
    extract_entity_and_program,
)

XMR = "4" + "8" * 94  # 95-character Monero form
EVM = "0x" + "11" * 20
TRON = "TNiq9AXBp9EjUqhDhrwrfvAA8U3GUQZH81"


def _page(*lines: str) -> str:
    body = "; ".join(lines)
    return f"<html><body><h1>Cyber-related Designations</h1><p>{body}</p></body></html>"


def test_monero_address_is_read_whole_and_never_truncated() -> None:
    stats: dict[str, int] = {}
    out = extract_addresses_with_evidence(_page(f"Digital Currency Address - XMR {XMR}"), stats)
    assert set(out) == {XMR}
    assert out[XMR] == {("monero", "ticker")}
    assert all(len(k) != 90 for k in out)
    assert stats == {}


def test_unknown_ticker_is_not_guessed_even_by_shape() -> None:
    stats: dict[str, int] = {}
    out = extract_addresses_with_evidence(_page(f"Digital Currency Address - ZZZ {EVM}"), stats)
    assert EVM not in out
    assert stats["skipped_unknown_ticker"] == 1


def test_known_ticker_with_a_foreign_token_is_skipped() -> None:
    stats: dict[str, int] = {}
    out = extract_addresses_with_evidence(_page(f"Digital Currency Address - XMR {EVM}"), stats)
    # the ticker says Monero, the token is a 0x address → not attributed by ticker; the
    # shape pass still sees a plain EVM address on the page
    assert out.get(EVM) == {("ethereum", "shape")}
    assert stats["skipped_shape_mismatch"] == 1


def test_ticker_and_shape_paths_still_agree_on_ordinary_rows() -> None:
    out = extract_addresses_with_evidence(
        _page(f"Digital Currency Address - ETH {EVM}", f"Digital Currency Address - TRX {TRON}")
    )
    assert out[EVM] == {("ethereum", "ticker")}
    assert out[TRON] == {("tron", "ticker")}


def test_h1_search_is_skipped_without_a_closing_tag() -> None:
    torn = "<html><body>" + "<h1>" * 5000 + "Digital Currency Address - ETH " + EVM
    title, _programs, _date = extract_entity_and_program(torn)
    assert title == ""


def test_rekt_network_names_are_case_insensitive() -> None:
    assert _network_chain("Avalanche") == _network_chain("avalanche") == "avalanche_c"
    assert _network_chain("ETHEREUM") == "ethereum"
    assert _network_chain(" Optimism ") == "optimism"
    assert _network_chain("") is None and _network_chain(None) is None


def test_62_character_bech32_addresses_are_read() -> None:
    """P2WSH / taproot addresses are 62 characters; the old {38,58} cap missed them."""
    p2wsh = "bc1q" + "w7vfgv3r5vnehafl0y95" + "a" * 38  # 62 chars, synthetic
    assert len(p2wsh) == 62
    out = extract_addresses_with_evidence(_page(f"Digital Currency Address - XBT {p2wsh}"))
    assert out[p2wsh] == {("bitcoin", "ticker")}
    out2 = extract_addresses_with_evidence(_page(f"wallet {p2wsh} mentioned without a ticker"))
    assert out2[p2wsh] == {("bitcoin", "shape")}
