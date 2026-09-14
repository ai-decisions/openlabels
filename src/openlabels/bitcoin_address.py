"""Bitcoin legacy address (P2PKH / P2SH) base58check validator.

Needed because OFAC files Omni-layer USDT under "Digital Currency Address -
USDT" with a plain Bitcoin address (SUEX, Chatex, Garantex rows in the
2026-09-10 SDN): the ticker says USDT, the chain is Bitcoin. Mapped by
ticker alone those rows fell to "unknown" and were dropped. Only the
base58check legacy forms are covered — Omni does not use bech32. Version
bytes: 0x00 (P2PKH, "1…") and 0x05 (P2SH, "3…"), mainnet only.
"""

from __future__ import annotations

import hashlib

# Same base58 alphabet and decoder as Tron (both are Bitcoin-style base58check).
from openlabels.tron_address import _b58decode

_MAINNET_VERSIONS = frozenset({0x00, 0x05})


def is_base58check(addr: object) -> bool:
    """True only for a checksum-valid Bitcoin mainnet P2PKH/P2SH address."""
    if not isinstance(addr, str) or not 26 <= len(addr) <= 35 or addr[0] not in "13":
        return False
    try:
        raw = _b58decode(addr)
    except ValueError:  # non-base58 character
        return False
    if len(raw) != 25 or raw[0] not in _MAINNET_VERSIONS:
        return False
    payload, checksum = raw[:21], raw[21:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
