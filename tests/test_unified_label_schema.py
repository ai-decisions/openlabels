"""UnifiedLabelRecord schema + loader."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from openlabels.unified import (
    LabelEntry,
    UnifiedLabelRecord,
    load_unified_labels,
)


def test_legacy_record_without_vasp_fields_parses() -> None:
    """Legacy v1 records must still parse."""
    payload = {
        "address": "0x28c6c06298d514db089934071355e5743bf21d60",
        "labels": [
            {
                "name": "Binance 14",
                "type": "exchange",
                "source": "known_exchanges",
                "chain": "ethereum",
            }
        ],
        "is_ai_agent": False,
        "is_illicit": False,
        "is_exchange": True,
        "chain": "ethereum",
    }
    rec = UnifiedLabelRecord.model_validate(payload)
    assert rec.is_exchange is True
    assert rec.jurisdiction is None
    assert rec.license_id is None
    assert rec.regulator is None
    assert rec.license_status is None
    assert rec.last_verified is None
    assert rec.entity_name is None
    assert rec.category is None
    assert rec.sanctioned is False
    assert rec.sanctions_reference is None
    assert rec.source_url is None
    assert rec.source_date is None
    assert len(rec.labels) == 1
    assert rec.labels[0].name == "Binance 14"


def test_vasp_enriched_record_parses() -> None:
    """Record with full VASP metadata."""
    now = datetime.now(UTC)
    payload = {
        "address": "0xbinancehot",
        "chain": "ethereum",
        "labels": [],
        "is_exchange": True,
        "jurisdiction": "MT",
        "license_id": "MFSA-VFA-2024-001",
        "regulator": "MFSA",
        "license_status": "active",
        "last_verified": now.isoformat(),
    }
    rec = UnifiedLabelRecord.model_validate(payload)
    assert rec.jurisdiction == "MT"
    assert rec.license_status == "active"
    assert rec.last_verified == now


def test_attributed_tron_record_parses() -> None:
    """v2.1 record — OFAC-attributed Tron sanctioned address."""
    from datetime import date as date_cls

    payload = {
        "address": "0xd1a3bdf9f3bb5d7d7c3e9b4a7c92e0e1c8d2a4f0",
        "chain": "tron",
        "labels": [
            {
                "name": "Example Entity",
                "type": "sanctioned",
                "source": "ofac_sdn",
                "chain": "tron",
            }
        ],
        "is_illicit": True,
        "entity_name": "Example Entity",
        "category": "sanctioned",
        "sanctioned": True,
        "sanctions_reference": "OFAC SDN-00000",
        "source_url": "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV",
        "source_date": "2026-05-08",
    }
    rec = UnifiedLabelRecord.model_validate(payload)
    assert rec.entity_name == "Example Entity"
    assert rec.category == "sanctioned"
    assert rec.sanctioned is True
    assert rec.sanctions_reference == "OFAC SDN-00000"
    assert rec.source_date == date_cls(2026, 5, 8)


def test_invalid_category_rejected() -> None:
    payload = {
        "address": "0xabc",
        "chain": "tron",
        "category": "not_a_real_category",
    }
    with pytest.raises(ValidationError):
        UnifiedLabelRecord.model_validate(payload)


def test_invalid_license_status_rejected() -> None:
    payload = {
        "address": "0xabc",
        "chain": "ethereum",
        "license_status": "revoked_pending",  # not in literal
    }
    with pytest.raises(ValidationError):
        UnifiedLabelRecord.model_validate(payload)


def test_label_entry_custom_type_allowed() -> None:
    """Schema accepts custom type strings for forward-compat, not only literal."""
    entry = LabelEntry(name="FooDAO", type="custom_tag", source="manual", chain="polygon")
    assert entry.type == "custom_tag"


def test_load_unified_labels_from_file(tmp_path: Path) -> None:
    labels_file = tmp_path / "unified_labels.json"
    labels_file.write_text(
        json.dumps(
            {
                "0xaaa": {
                    "address": "0xaaa",
                    "chain": "ethereum",
                    "labels": [
                        {
                            "name": "Tornado Cash 0.1 ETH",
                            "type": "mixer",
                            "source": "known_mixers",
                            "chain": "ethereum",
                        }
                    ],
                    "is_illicit": True,
                },
                "0xbbb": {
                    "address": "0xbbb",
                    "chain": "ethereum",
                    "labels": [],
                    "is_exchange": True,
                    "jurisdiction": "US-NY",
                    "license_id": "NYDFS-BL-2015-009",
                    "regulator": "NY DFS",
                    "license_status": "active",
                },
            }
        )
    )
    records = load_unified_labels(labels_file)
    assert set(records.keys()) == {"0xaaa", "0xbbb"}
    assert records["0xaaa"].is_illicit is True
    assert records["0xaaa"].jurisdiction is None
    assert records["0xbbb"].regulator == "NY DFS"
    assert records["0xbbb"].license_status == "active"


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_unified_labels(tmp_path / "does_not_exist.json")


def test_loader_back_fills_address_key(tmp_path: Path) -> None:
    """If JSON payload omits 'address', loader injects dict key."""
    labels_file = tmp_path / "unified_labels.json"
    labels_file.write_text(
        json.dumps(
            {
                "0xccc": {
                    "chain": "tron",
                    "labels": [],
                }
            }
        )
    )
    records = load_unified_labels(labels_file)
    assert records["0xccc"].address == "0xccc"
