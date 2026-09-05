# First-party curated labels

`ai-decisions-first-party-labels.yaml` is a GraphSense-style TagPack of address labels curated by
AI DECISIONS. It is the only label *data* shipped in this repository; everything else here is tooling
(see the top-level README, section "No data dumps"). Every tag carries a `provenance` marker in its
`context`:

- **`sourced`** — a public record supports the row and its `source` URI points at that document: a
  first-party on-chain extraction with the method stated below, or a US Treasury / OFAC publication.
- **`curated`** — AI DECISIONS' own seed list. The label is what we hold; the per-row public record was
  not recorded when the list was compiled. Treat these rows as leads to verify on a public explorer,
  not as findings. Their `source` URI points at the set's section in this file (or at the public
  project the set was drawn from) rather than at a per-address document.

The label text states what we hold and nothing more. An interaction is not a finding about the holder;
a removed sanctions listing is stated as removed; a name corrected against a sanctions list keeps the
old text in `context.previously_recorded_as`.

## Sourced sets

### Tornado Cash interactors

Ethereum addresses that appear as `from_address` of a transaction whose `to_address` is a Tornado Cash
router, proxy or pool contract. Extracted by AI DECISIONS from Ethereum transaction data (full-history
scan, 2026); a sample, not the population. The label is the on-chain fact ("Tornado Cash interactor
(sender)"); no abuse category is attached, because sending to a privacy protocol is not by itself a
finding about the holder. Verification: open the address on any Ethereum explorer and look for an
outgoing transaction to a Tornado Cash contract.

### Tornado Cash contracts and sanctioned wallets

Four Ethereum addresses whose facts are carried by OFAC publications, cited per row:

- `0x8589…fda16` Tornado Cash router and `0x7221…b6967` Tornado Cash proxy — designated by OFAC on
  2022-08-08 (Cyber-related Designation) and **removed from the SDN list on 2025-03-21**; both dates are
  linked in the tag context. No `sanction` category is attached, since the listing was removed.
- `0x098b…2f96` — the SDN entry *Lazarus Group* (designation 2022-04-14), publicly reported as the Ronin
  Bridge exploiter; on the SDN list in our OFAC copy of the build date; category `sanction`.
- `0x7f19…8102` — the SDN entry *Secondeye Solution*; on the SDN list in our OFAC copy of the build
  date; category `sanction`. Our earlier internal text for this address was "Lazarus (DPRK)"; it was
  corrected to the SDN entry name on 2026-09-06 and the old text is kept in `context`.

### Virtuals Protocol token contract

`0x44ff…bf73` — the VIRTUAL ERC-20 contract on Ethereum mainnet; name and symbol read from the
contract itself.

## Curated sets

### Exchange hot wallets (curated)

20 Ethereum addresses of well-known exchange hot wallets (Binance, Coinbase, Kraken, KuCoin, Huobi, OKX,
Poloniex, Gemini) from AI DECISIONS' seed list; category `exchange`. The attribution is public knowledge
and is easy to confirm on any explorer, but no per-address document was recorded — hence `curated`.

### Ethereum bots, agents and protocol contracts (curated)

28 addresses from a list compiled from public forensics work: MEV bots and sandwich/arbitrage searchers,
liquidation bots (Aave, Compound), Gelato executors and Chainlink keepers, bot-operator EOAs, and a
handful of canonical protocol contracts (ETH2 deposit contract, Lido stETH, Compound cETH/cUSDC/COMP,
Aave V2/V3 pools, WETH, 1inch, 0x exchange proxy). `context.type` / `context.subtype` carry our
classification; protocol contracts are `kind: contract`. One placeholder row of the internal list is not
published (a placeholder is not a label).

### MEV searchers (curated)

12 searcher addresses ranked by profit in public dashboards (libMEV) and mev-inspect-py output;
`source` points at the mev-inspect-py project. Label "MEV searcher".

### Block builders (curated)

6 builder fee-recipient addresses (rsync, builder0x69, eth-builder, flashbots-builder, titan) from the
public mev-boost relay builder lists; `source` points at the mev-boost-relay project.

### Curated without a public record

`0x940f…f4f1` "DPRK mixer" — held in our store without a cited public record and not on the OFAC copy
of 2026-09-05. Published as `curated` so that the label can be checked, not relied upon.

## Format and licence

GraphSense TagPack YAML (`title`, `creator`, `lastmod`, `tags[]` with `address`, `currency`, `label`,
`source`, optional `category`, and a JSON `context` with `provenance` plus the method or the supporting
facts). Validate with
`python3 -m openlabels.tagpack.generate_tagpack --validate data/first-party/ai-decisions-first-party-labels.yaml`.
The file is published under the repository licence (Apache-2.0); OFAC publications are US government
public information.

## Corrections

If a row is wrong, open an issue naming the address and the evidence; a row whose source no longer
supports it is removed or restated, never silently edited.
