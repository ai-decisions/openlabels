# Security posture — openlabels

A one-page statement of how this repository is built and released.
Vulnerability reporting: see [`SECURITY.md`](../SECURITY.md).

## Build & release integrity

- Every commit runs the full CI gate on public GitHub-hosted runners:
  compile of every module, lint, sanitize gate, unit tests, and a
  **reproducibility job** — the deterministic pipeline (fixed public
  OFAC subset → unified store → label set → TagPack) is rebuilt from a
  clean clone and its shas must match the reference values in
  `README.md`. Two independent runners produced identical shas.
- The sanitize gate (`tools/sanitize_gate.py`) fails the build on:
  secret-shaped values, storage URIs and machine-local paths, internal
  project markers, and files named after redistribution-restricted
  sources (FCA register content, OpenSanctions CC-BY-NC, Dune Spellbook
  BSL). In CI it runs in `--public-mode`, which checks that generic
  ruleset; installation-specific identifiers are checked out-of-band
  before every publication, from a pattern file that is deliberately not
  part of this repository — a public checker must not double as an
  inventory of the values it guards against.

## Data boundary

- No regulator data dumps in the repo; scrapers reproduce data from
  primary origins on demand.
- Fixtures are limited to a small fixed subset of the public OFAC SDN
  list, with provenance recorded in `tests/data/README.md`.

## Runtime posture

- Pure-Python tooling, no network access except explicit scraper
  fetches of primary public sources over HTTPS.
- No telemetry. No writes outside paths the caller passes in.
- Optional per-source API keys come from environment variables only.

## Trust anchors

- License: Apache-2.0 (`LICENSE`), attribution and per-source terms in
  `NOTICE`.
- Contributions: DCO sign-off required.
- Contact: mail@aidecisions.ai
