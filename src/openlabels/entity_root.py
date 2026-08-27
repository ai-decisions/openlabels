"""Entity name normalization.

Strips common exchange-address suffixes so labels like "Binance 14", "Binance Hot
Wallet", "Binance: Deposit 3" collapse to the same entity root "Binance".

Handles None/empty names gracefully (such entries do occur in real label stores).
"""
from __future__ import annotations

import re

# Strip trailing ` #N` or ` N` where N is a small integer (1-4 digits),
# preceded by whitespace — targets "Binance 14", "Binance #3".
# Does NOT strip digits from addresses (no preceding space means not a suffix).
_TRAILING_NUM_RE = re.compile(r"\s+#?\d{1,4}\s*$")

# .com / .net / .io / .exchange TLDs appended to exchange names in some sources.
_TLD_SUFFIXES = (".com", ".net", ".io", ".exchange", ".co")

_SUFFIXES = (
    " Hot Wallet",
    " Cold Wallet",
    " Cold Storage",
    " Hot Storage",
    " Deposit",
    " Settlement",
    " Trading",
    " Exchange",
    " Reserve",
    " Wallet",
)


def entity_name_root(name: str | None) -> str:
    """Normalize label name to a canonical entity root.

    Returns "" for None/empty/whitespace input (never raises).
    """
    if name is None:
        return ""
    cleaned = _TRAILING_NUM_RE.sub("", name).strip()
    if not cleaned:
        return ""
    # Strip TLDs (Binance.com -> Binance) iff result still has letters.
    for tld in _TLD_SUFFIXES:
        if cleaned.endswith(tld) and len(cleaned) > len(tld) + 1:
            cleaned = cleaned[: -len(tld)]
            break
    # Iteratively strip role suffixes.
    changed = True
    while changed:
        changed = False
        for suf in _SUFFIXES:
            if cleaned.endswith(suf):
                cleaned = cleaned[: -len(suf)].strip()
                changed = True
                break
    cleaned = cleaned.rstrip(":").rstrip("-").strip()
    return cleaned
