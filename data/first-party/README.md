# First-party curated labels

`ai-decisions-first-party-labels.yaml` is a GraphSense-style TagPack of address labels that AI DECISIONS
curated itself. It is the only label *data* shipped in this repository; everything else here is tooling
(see the top-level README, section "No data dumps"). Two rules hold for every row:

1. the row is either a **first-party on-chain extraction** (method stated below and reproducible from
   public chain data) or a fact carried by a **cited public primary source** (a US Treasury / OFAC
   publication), and the `source` URI of the tag points at exactly that document;
2. the label text states what the source supports and nothing more. An interaction is not a finding
   about the holder; a removed sanctions listing is stated as removed.

Rows are added only when both rules hold. Labels that AI DECISIONS holds from third-party name tags,
dashboards or uncited curation are **not** in this file.

## Sets

### Tornado Cash interactors

Ethereum addresses that appear as `from_address` of a transaction whose `to_address` is a Tornado Cash
router, proxy or pool contract. The set was extracted by AI DECISIONS from Ethereum transaction data
(full-history scan, 2026); it is a sample, not the population. The label is the on-chain fact
("Tornado Cash interactor (sender)"); no abuse category is attached, because sending to a privacy
protocol is not by itself a finding about the holder. Verification: open the address on any Ethereum
explorer and look for an outgoing transaction to a Tornado Cash contract.

### Tornado Cash contracts and the Ronin Bridge exploiter

Three well-known Ethereum addresses whose facts are carried by OFAC publications, cited per row:

- `0x8589…fda16` Tornado Cash router and `0x7221…b6967` Tornado Cash proxy — designated by OFAC on
  2022-08-08 (Cyber-related Designation) and **removed from the SDN list on 2025-03-21**; both dates
  are linked in the tag context. No `sanction` category is attached, since the listing was removed.
- `0x098b…2f96` — the SDN entry *Lazarus Group* (designation 2022-04-14), publicly reported as the Ronin
  Bridge exploiter; on the SDN list in our OFAC copy of the build date; category `sanction`.

### Virtuals Protocol token contract

`0x44ff…bf73` — the VIRTUAL ERC-20 contract on Ethereum mainnet; name and symbol read from the
contract itself.

## Format and licence

GraphSense TagPack YAML (`title`, `creator`, `lastmod`, `tags[]` with `address`, `currency`, `label`,
`source`, optional `category`, and a JSON `context` with the method or the supporting facts). Validate
with `python3 -m openlabels.tagpack.generate_tagpack --validate data/first-party/ai-decisions-first-party-labels.yaml`.
The file is published under the repository licence (Apache-2.0); OFAC publications are US government
public information.

## Corrections

If a row is wrong, open an issue naming the address and the evidence; a row whose source no longer
supports it is removed or restated, never silently edited.
