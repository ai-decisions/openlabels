# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately** to **mail@aidecisions.ai**.
Do not open a public issue for security problems. We will acknowledge
your report and coordinate disclosure with you; a fix or a mitigation
plan is published before details are.

This policy covers the code in this repository. Issues in the hosted
AI DECISIONS platform (aidecisions.ai) go to the same address.

## What this code does — and does not do

- Scrapers fetch **public regulator registers and sanctions lists**
  over HTTPS from their primary origins. No telemetry, no callbacks,
  no data is sent anywhere by this code.
- No credentials are required to run the tools. The only optional
  secret is a user-supplied API key for sources that require one,
  read from environment variables — never from files in this repo.
- The repository ships **no data dumps** and no model weights
  (see `README.md` → Boundary).

## Supply chain

- CI (GitHub Actions, standard runners) gates every change:
  module compile, lint, **sanitize gate** (`tools/sanitize_gate.py` —
  a generic scan for secrets, storage URIs, machine-local paths and
  restricted-source data), unit tests, and a determinism job that
  recomputes the pipeline shas published in `README.md`.
- Actions are pinned to major versions; runtime dependencies are
  minimal (`pydantic`, `pyarrow`; extras: `pyyaml`, `pdfplumber`).
- Contributions require a DCO sign-off (`git commit -s`).
