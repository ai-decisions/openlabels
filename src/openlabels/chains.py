"""Canonical chain names for the unified label store.

Sources spell chains differently (dawsbot chainId 100 → "xdai", crypto-rekts
"Gnosis", "Avax" vs "Avalanche", short tickers "eth"/"trx"/"btc"). The store and
every consumer key by (chain, address), so two spellings of one chain are two
keys nobody queries together — the product had to alias `xdai` → `gnosis` at
read time (2026-08-21). Normalise once, at ingest (contract P, 2026-09-14).

`EVM_CHAINS` is the set of chains whose addresses are 0x-hex; an EVM-shaped
address may only carry one of these (or "evm" when the source does not say
which — never a guessed default).
"""

from __future__ import annotations

_CANONICAL: dict[str, str] = {
    "eth": "ethereum",
    "trx": "tron",
    "btc": "bitcoin",
    "arb": "arbitrum",
    "arb1": "arbitrum",
    "op": "optimism",
    "gno": "gnosis",
    "xdai": "gnosis",
    "gnosis chain": "gnosis",
    "matic": "polygon",
    "avax": "avalanche_c",
    "avalanche": "avalanche_c",
    "bnb chain": "bsc",
    "bnb smart chain": "bsc",
    "binance": "bsc",
    "etc": "ethereum_classic",
    "ltc": "litecoin",
    "xmr": "monero",
    "sol": "solana",
    "doge": "dogecoin",
}

EVM_CHAINS: frozenset[str] = frozenset(
    {
        "ethereum",
        "ethereum_classic",
        "bsc",
        "polygon",
        "avalanche_c",
        "arbitrum",
        "optimism",
        "base",
        "fantom",
        "cronos",
        "harmony",
        "heco",
        "okex",
        "gnosis",
        "celo",
        "moonbeam",
        "moonriver",
        "aurora",
        "evm",  # EVM address, chain not stated by the source
    }
)


def normalize_chain(raw: object) -> str:
    """Canonical lower-case chain name; unknown spellings pass through lower-cased."""
    s = str(raw or "").strip().lower()
    return _CANONICAL.get(s, s)
