# Test fixtures — provenance

## `ofac_sdn_subset.csv` — real OFAC SDN rows (US Government work, public domain)

Fixed public OFAC subset used as the input of the reproducibility path.

- Source: `https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV`
- Fetched: 2026-08-24T23:32:39Z
- Full-file size / sha256 at fetch time: 5,668,063 bytes /
  `62fec6e8a8bc483ed59ad72b876b16e17c01b39f2b83886b78f01f71d2d4aad0`
- Extraction rule (mechanical): CR characters stripped (the feed is CRLF),
  then the first 8 lines that contain `Digital Currency Address` and are
  pure printable ASCII (entity names with non-ASCII characters excluded so
  the fixture stays byte-stable across editors and locales).
- Licence: a work of the US Government is not subject to copyright
  (17 U.S.C. 105).

## `raw_sample.json`, `batch_sample.jsonl` — synthetic

Invented example entities and addresses (0x1111…, 0x2222…, …) plus the
Bitcoin genesis address as a public constant. Tron entries use the base58check
encoding of twenty zero bytes: valid format, but it belongs to no real party,
because a fixture must never attach a label — least of all `sanctioned` — to a
real third-party contract. An
earlier revision labelled the live USDT TRC-20 contract as sanctioned.
No third-party dataset rows.
