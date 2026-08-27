"""Unified labels loader + Pydantic schema with VASP regulatory fields.

Schema is backward-compatible: records without v2 attribution fields
parse correctly (defaults to None/False). Records WITH fields validate
them (EntityCategory literal, ISO 3166-1/2 jurisdiction, license_status).

Schema versions:
- v1: address, chain, labels, is_ai_agent, is_illicit, is_exchange
- v2: + jurisdiction, license_id, regulator, license_status
- v2.1: + entity_name, category, sanctioned, sanctions_reference,
  source_url, source_date — promotes each record from bag-of-flags to
  an attributed entity record: every attribution is citable to an
  external source on a specific date, so it survives due-diligence review.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

LabelType = Literal[
    "exchange",
    "illicit",
    "licit",
    "mixer",
    "sanctioned",
    "ai_agent",
    "defi_protocol",
    "bridge",
    "staking",
    "unknown",
]

LicenseStatus = Literal["active", "revoked", "pending"]

# Entity category enum. A typed output that downstream consumers carry
# in a `category` field, so the set is deliberately small and stable.
EntityCategory = Literal[
    "vasp",  # regulated exchange / custodian
    "exchange_depositor",  # wallet used by an exchange customer for deposits
    "mixer",  # tumblers, mixers, coinjoin coordinators
    "defi_protocol",  # AMM / lending / staking contracts
    "sanctioned",  # OFAC/UN/EU-listed (category, not chain)
    "scam",  # phishing, rugpulls, Ponzi schemes
    "personal",  # individuals / non-commercial
    "unknown",  # not yet attributed
]


class LabelEntry(BaseModel):
    """One label attached to an address (may have multiple per address)."""

    model_config = ConfigDict(extra="allow")

    name: str = Field(..., max_length=256)
    type: LabelType | str = Field(..., max_length=64)
    source: str = Field(..., max_length=128)
    chain: str = Field(..., max_length=32)


class UnifiedLabelRecord(BaseModel):
    """One address in a unified label store (unified_labels.json).

    VASP fields may be NULL-populated until filled from
    jurisdiction-specific register scrapes. Having them in the schema
    from the start means scripts/loaders that emit records can carry
    partial data without breaking older consumers.
    """

    model_config = ConfigDict(extra="allow")

    address: str = Field(..., min_length=1, max_length=256)
    chain: str = Field(..., max_length=32)
    labels: list[LabelEntry] = Field(default_factory=list)

    is_ai_agent: bool = False
    is_illicit: bool = False
    is_exchange: bool = False

    jurisdiction: str | None = Field(
        default=None,
        max_length=8,
        description="ISO 3166-2 region code (e.g. 'MT', 'US-NY', 'SG')",
    )
    license_id: str | None = Field(default=None, max_length=128)
    regulator: str | None = Field(default=None, max_length=128)
    license_status: LicenseStatus | None = None
    last_verified: datetime | None = None

    # v2.1 attribution fields. `entity_name` is the named actor this
    # address belongs to (e.g. "Binance", "Tornado Cash", "Garantex");
    # `category` is the typed classification above.
    # `sanctioned` + `sanctions_reference` capture OFAC/UN/EU
    # designations directly rather than encoding them in `labels[].type`.
    # `source_url` + `source_date` exist for DD audit trails — every
    # attribution must be citable to an external source on a specific
    # date, or it cannot survive due-diligence review.
    entity_name: str | None = Field(default=None, max_length=128)
    category: EntityCategory | None = None
    sanctioned: bool = False
    sanctions_reference: str | None = Field(default=None, max_length=128)
    source_url: str | None = Field(default=None, max_length=512)
    source_date: date | None = None


def load_unified_labels(path: str | Path) -> dict[str, UnifiedLabelRecord]:
    """Load unified_labels.json from a local path into typed records.

    Remote paths are not fetched here — download to a local path first.
    """

    local = Path(path)
    if not local.exists():
        raise FileNotFoundError(f"unified_labels.json not found at {local}")

    with local.open("r", encoding="utf-8") as fh:
        raw: dict[str, dict] = json.load(fh)

    out: dict[str, UnifiedLabelRecord] = {}
    for addr, payload in raw.items():
        payload.setdefault("address", addr)
        out[addr] = UnifiedLabelRecord.model_validate(payload)
    return out
