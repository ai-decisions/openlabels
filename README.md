# openlabels

Open tooling for on-chain address labels: a typed unified label-store
schema, parsers for public attribution sources (OFAC SDN, regulator
registers), scrapers for VASP registers across 9 jurisdictions,
registry builders (VASP / mixer / bridge), and a GraphSense-style
TagPack generator.

Built and used in production by [AI DECISIONS](https://aidecisions.ai/).

## Boundary — what is open here, and what is not

This repository is the **instrument**, not the result of applying it:

**Open (this repo):**
- `openlabels` package: unified label schema (Pydantic v2), chain-aware
  address case policy, Tron base58check↔hex converter, OFAC SDN parser,
  entity-name normalisation.
- Pipelines: merge raw label sources into a unified store; append-only
  label-set builder with per-row provenance.
- Scrapers for public VASP registers: ESMA (EU), FCA (UK), FinCEN (US),
  NYDFS (US-NY), MAS (SG), SFC (HK), JFSA (JP), FINMA (CH), VARA (AE).
- Registry builders: VASP directory merge, mixer registry, bridge
  registry (L2BEAT-sourced).
- TagPack generator with per-row source provenance and local validation.

**Not open (deliberately):**
- Our assembled label store, training label sets, graph substrate,
  trained models, and serving infrastructure. Those are the *result* of
  running these tools plus proprietary attribution work.

## No data dumps

The repository ships **no regulator data dumps**. Every scraper fetches
the primary source itself, so a clean clone reproduces the data from
the same origin the tools were built against. Reasons are legal, not
technical: several registers (e.g. the UK FCA Financial Services
Register) restrict redistribution of their content. See `NOTICE` for
per-source terms. Outputs derived from CC-BY-NC sources
(OpenSanctions) or BSL-licensed sources (Dune Spellbook) are likewise
excluded and must not be added.

## Install

```bash
pip install -e .            # core: pydantic + pyarrow
pip install -e .[tagpack]   # + pyyaml for the TagPack generator
pip install -e .[jfsa]      # + pdfplumber for the JP JFSA PDF register
```

Python ≥ 3.11.

## Quickstart

```python
from openlabels import UnifiedLabelRecord, load_unified_labels
from openlabels.address_case import canonical_case, is_case_destroyed
from openlabels.tron_address import base58check_to_hex

records = load_unified_labels("unified_labels.json")
base58check_to_hex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
# '0xa614f803b6fd780986a42c78ec9c7f77e6ded13c'
```

Pipelines and scrapers are runnable modules:

```bash
python -m openlabels.scrapers.scrape_esma_mica_register --help
python -m openlabels.pipelines.merge_to_unified --help
python -m openlabels.tagpack.generate_tagpack --help
```

## Address case policy

Blanket lowercasing destroys base58check addresses (BTC legacy, XRP,
SOL, XMR, TRON T-form, …) irreversibly — case is payload there. Every
store-ingest path in this repo normalises through
`openlabels.address_case.canonical_case` and refuses case-destroyed
rows. If you take one thing from this repo, take that.

## Secrets

Two scrapers need credentials, provided via environment variables only
(never committed): `FCA_API_EMAIL`/`FCA_API_KEY` (register at
register.fca.org.uk/Developer/) and `TRONSCAN_API_KEY`.

## Reproducibility

`tests/test_pipeline_determinism.py` builds the full pipeline (fixed public
OFAC SDN subset + synthetic fixtures → unified store → label-set parquet →
TagPack) twice and asserts byte-identical artefacts. Reference sha256 values,
reproduced independently on Python 3.11 and 3.12 CI runners:

```
unified_store      adbcf55e8ca19331076f20bf67d61102cf934c96d48e3f3c97a4c2c317625673
label_set_parquet  e0f5b64391dcf16e2c050b2a99b68895d6daae8c204fb40bdd220cd40d95608e
tagpack            2110631eaaccc602bf375ebc1accb7a9324cac925a4210827fb84a27e2958066
```

Fixture provenance: `tests/data/README.md`.

## Contributing

Contributions are accepted under the Developer Certificate of Origin
(sign-off line in commits, `git commit -s`). License: Apache-2.0, see
`LICENSE` and `NOTICE`.
