"""sanitize_incoming: schema-align incoming raw records without inventing
attribution — out-of-enum scalars stash to _raw fields, malformed
source_date truncates/nulls, valid fields pass untouched."""

from __future__ import annotations

from openlabels.pipelines.merge_to_unified import sanitize_incoming


def test_out_of_enum_category_stashed_not_mapped():
    rec, delta = sanitize_incoming({"category": "exchange"})
    assert rec["category"] is None
    assert rec["_category_raw"] == "exchange"
    assert delta["category_stashed"] == 1


def test_valid_category_untouched():
    rec, delta = sanitize_incoming({"category": "vasp"})
    assert rec["category"] == "vasp"
    assert "_category_raw" not in rec
    assert delta["category_stashed"] == 0


def test_out_of_enum_license_status_stashed():
    rec, delta = sanitize_incoming({"license_status": "issued"})
    assert rec["license_status"] is None
    assert rec["_license_status_raw"] == "issued"
    assert delta["license_status_stashed"] == 1


def test_datetime_source_date_truncated_to_date():
    rec, delta = sanitize_incoming({"source_date": "2026-05-09T14:22:31Z"})
    assert rec["source_date"] == "2026-05-09"
    assert rec["_source_date_raw"] == "2026-05-09T14:22:31Z"
    assert delta["date_truncated"] == 1


def test_empty_source_date_nulled():
    rec, delta = sanitize_incoming({"source_date": ""})
    assert rec["source_date"] is None
    assert delta["date_invalid_nulled"] == 1


def test_partial_source_date_nulled():
    rec, delta = sanitize_incoming({"source_date": "2009-03"})
    assert rec["source_date"] is None
    assert rec["_source_date_raw"] == "2009-03"
    assert delta["date_invalid_nulled"] == 1


def test_valid_iso_date_untouched():
    rec, delta = sanitize_incoming({"source_date": "2026-08-17"})
    assert rec["source_date"] == "2026-08-17"
    assert "_source_date_raw" not in rec
    assert delta["date_truncated"] == 0 and delta["date_invalid_nulled"] == 0
