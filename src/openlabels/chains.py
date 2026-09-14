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
    # Contract S (2026-09-14, gates B and C): one name per chain — XRP Ledger is `xrp`
    # (the Lambda and the store already said so); BNB Beacon Chain is `bnb_beacon`,
    # distinct from BNB Smart Chain (`bsc`). A bare "bnb" is resolved by address form
    # in resolve_bnb() — a 0x address can only be bsc.
    "ripple": "xrp",
    "bnb beacon chain": "bnb_beacon",
    "beacon": "bnb_beacon",
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


# Chains whose addresses are not 0x-hex. Together with EVM_CHAINS this is the allow-list
# of chain names the store may carry (contract S, S7): a spelling outside it is not a
# chain — it is a typo, a homoglyph or junk, and a label keyed under it is served to
# nobody. `multi` is a legacy value (197 records, 2026-09-14) kept until the v7 repair.
NON_EVM_CHAINS: frozenset[str] = frozenset(
    {
        "bitcoin",
        "bitcoin_cash",
        "bitcoin_sv",
        "bitcoin_gold",
        "litecoin",
        "dogecoin",
        "verge",
        "dash",
        "zcash",
        "monero",
        "tron",
        "solana",
        "xrp",
        "bnb_beacon",
        "multi",
    }
)
CANONICAL_CHAINS: frozenset[str] = EVM_CHAINS | NON_EVM_CHAINS


def normalize_chain(raw: object) -> str:
    """Canonical lower-case chain name; unknown spellings pass through lower-cased."""
    s = str(raw or "").strip().lower()
    return _CANONICAL.get(s, s)


def is_canonical_chain(name: object) -> bool:
    """True when `name` (already normalised) is a chain the store may carry."""
    return str(name or "") in CANONICAL_CHAINS


def resolve_bnb(chain: str, address: object) -> str:
    """A bare `bnb` names two chains; the address form decides (contract S, gate C):
    0x → BNB Smart Chain (`bsc`), anything else → BNB Beacon Chain (`bnb_beacon`)."""
    if chain != "bnb":
        return chain
    return "bsc" if str(address or "").strip().lower().startswith("0x") else "bnb_beacon"
