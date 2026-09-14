"""Chain inference must follow the address shape, not only the OFAC ticker.

OFAC files SDN-45404's Tron address TUCsTq7… under "Digital Currency Address -
XBT". Mapped by ticker it became a Bitcoin tag that resolves on no chain; the
GraphSense maintainers flagged it on our pack (graphsense-tagpacks#53,
2026-09-14). The converse also happens: Omni-layer USDT is filed under "USDT"
with a plain Bitcoin address and nowhere else (SUEX, Chatex rows), and by
ticker alone fell to "unknown". All addresses below are public OFAC SDN rows
or the Bitcoin genesis address; no label is attached — this is a format test.
"""

from __future__ import annotations

from openlabels.bitcoin_address import is_base58check as is_bitcoin_base58check
from openlabels.ofac_attributed import _infer_chain
from openlabels.tron_address import hex_to_base58check, is_base58check

TRON_UNDER_XBT = "TUCsTq7TofTCJRRoHk6RvhMoS2mJLm5Yzq"  # SDN-45404, ticker XBT in the feed
BTC_GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
OMNI_USDT_P2PKH = "16iWn2J1McqjToYLHSsAyS6En3QA8YQ91H"  # SDN row filed under USDT only (P2PKH)
OMNI_USDT_P2SH = "3LtcaPbCj87CwJHnRX3vh7c2y9RZQqeSy8"  # SDN row filed under USDT only (P2SH)


def test_valid_tron_address_is_tron_whatever_the_ticker() -> None:
    assert _infer_chain("XBT", TRON_UNDER_XBT) == "tron"
    assert _infer_chain("USDT", TRON_UNDER_XBT) == "tron"
    assert _infer_chain("TRX", TRON_UNDER_XBT) == "tron"


def test_bitcoin_ticker_with_bitcoin_address_unchanged() -> None:
    assert _infer_chain("XBT", BTC_GENESIS) == "bitcoin"


def test_tron_shape_with_bad_checksum_does_not_override_ticker() -> None:
    bad = TRON_UNDER_XBT[:-1] + ("1" if TRON_UNDER_XBT[-1] != "1" else "2")
    assert not is_base58check(bad)
    assert _infer_chain("XBT", bad) == "bitcoin"


def test_is_base58check_round_trip_and_rejects_non_strings() -> None:
    synthetic = hex_to_base58check("0x" + "00" * 20)  # twenty zero bytes, nobody's address
    assert is_base58check(synthetic)
    assert not is_base58check(None)
    assert not is_base58check("0x" + "00" * 20)


def test_omni_usdt_on_a_bitcoin_address_is_bitcoin() -> None:
    assert _infer_chain("USDT", OMNI_USDT_P2PKH) == "bitcoin"
    assert _infer_chain("USDT", OMNI_USDT_P2SH) == "bitcoin"
    assert _infer_chain("USDT", "0x" + "11" * 20) == "ethereum"
    assert _infer_chain("USDT", "not-an-address") == "unknown"


def test_bitcoin_base58check_versions_and_checksum() -> None:
    assert is_bitcoin_base58check(BTC_GENESIS)
    assert is_bitcoin_base58check(OMNI_USDT_P2SH)
    assert not is_bitcoin_base58check(BTC_GENESIS[:-1] + ("b" if BTC_GENESIS[-1] != "b" else "c"))
    assert not is_bitcoin_base58check(TRON_UNDER_XBT)  # version byte 0x41 is Tron, not Bitcoin
    assert not is_bitcoin_base58check("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")  # bech32 out of scope
    assert not is_bitcoin_base58check(None)
