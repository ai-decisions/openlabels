"""entity_name_root — regression assertions.

The trailing-digit regex must strip role suffixes and wallet numbers from
entity labels without ever eating characters of a bare address (no
preceding space means the digits are payload, not a suffix).
"""

from __future__ import annotations

from openlabels.entity_root import entity_name_root


def test_none_and_empty_inputs() -> None:
    assert entity_name_root(None) == ""
    assert entity_name_root("") == ""
    assert entity_name_root("   ") == ""


def test_numbered_wallets_collapse() -> None:
    assert entity_name_root("Binance 14") == "Binance"
    assert entity_name_root("Binance: Deposit 3") == "Binance"
    assert entity_name_root("Kraken Cold Storage 2") == "Kraken"


def test_role_suffixes_stripped() -> None:
    assert entity_name_root("Binance Hot Wallet") == "Binance"
    assert entity_name_root("Coinbase Exchange") == "Coinbase"


def test_tld_suffixes_stripped() -> None:
    assert entity_name_root("Binance.com") == "Binance"
    assert entity_name_root("Kraken.com") == "Kraken"
    assert entity_name_root("Huobi.com") == "Huobi"


def test_addresses_never_truncated() -> None:
    addr = "1SyntheticBase58AddrNoSpace123"  # not a real address — regex-behaviour probe
    assert entity_name_root(addr) == addr
