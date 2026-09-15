"""Contract R (2026-09-15) — sanctions semantics at the data layer.

R1  parse_ofac_press_releases reads the SECTION an address sits in on an OFAC action
    page: designation / change / removal. A removal page yields `type: sanctions_removed`
    and a record that asserts nothing illicit. Two real cached pages (2025-03-21 Tornado
    Cash removal; 2022-11-08 deletion and re-designation the same day) plus synthetic
    pages; `extract_addresses_with_evidence` keeps its pre-R output.
R2  parse_opensanctions types a CryptoWallet by ITS source's topics and datasets:
    `sanctioned` only for the `sanction` topic / a sanctions-list dataset; ransomwhere →
    illicit/ransomware; il_mod_crypto → illicit/terror_financing; FBI Lazarus → illicit/hack.
R3  merge: the label key carries `context.source_url`; the record's standing follows
    its dated press-release labels (add → removal; add → removal → add; add without
    context), a sanctioned label from another source keeps the record sanctioned.
Addresses are synthetic or public OFAC rows read from the cached pages themselves.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from openlabels.pipelines.merge_to_unified import (
    merge_label_entries,
    merge_records,
    press_release_status,
    reconcile_press_release_status,
)
from openlabels.pipelines.parse_ofac_press_releases import (
    ACTION_CHANGE,
    ACTION_DESIGNATION,
    ACTION_REMOVAL,
    action_date_from_link,
    classify_section_header,
    extract_address_actions,
    extract_addresses_with_evidence,
    net_action,
    page_net_action,
    press_release_records,
)
from openlabels.pipelines.parse_opensanctions import classify_wallet, process_crypto_wallet

EVM_A = "0x" + "11" * 20
EVM_B = "0x" + "22" * 20
EVM_C = "0x" + "33" * 20
EVM_D = "0x" + "44" * 20
TRON_T = "TNiq9AXBp9EjUqhDhrwrfvAA8U3GUQZH81"
TORNADO_ROUTER = "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b"  # Tornado Cash: Router (OFAC 2022)

_PAGES = Path(__file__).resolve().parents[2].parent / "data" / "labels_raw" / "ofac_action_pages"
_REMOVAL_PAGE = _PAGES / "action_20250321_c8a428aecc59.html"
_REDESIGNATION_PAGE = _PAGES / "action_20221108_8cbf25b41f8c.html"
_DESIGNATION_PAGE = _PAGES / "action_20220808_8378c7bf1919.html"


def _page(*blocks: str) -> str:
    body = "".join(f"<p>{b}</p>" for b in blocks)
    return f"<html><body><h1>Cyber-related Designation</h1>{body}</body></html>"


# --- R1: section headers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "action"),
    [
        ("The following individuals have been added to OFAC's SDN List:", ACTION_DESIGNATION),
        ("The following entity has been added to OFAC's SDN List:", ACTION_DESIGNATION),
        ("The following additions have been made to OFAC's list of SDNs:", ACTION_DESIGNATION),
        ("The following deletions have been made to OFAC's SDN List:", ACTION_REMOVAL),
        ("The following names have been removed from OFAC's SDN List:", ACTION_REMOVAL),
        ("The following changes have been made to OFAC's SDN List:", ACTION_CHANGE),
        ("The following administrative changes have been made to OFAC's SDN List:", ACTION_CHANGE),
        ("In addition, the following changes to the SDN list occurred today:", ACTION_CHANGE),
        (
            'The following language, "Secondary sanctions risk," has been added to the below names:',
            ACTION_CHANGE,
        ),
        ("The names below have been updated to include the following language:", ACTION_CHANGE),
        # an introduction naming several kinds of change opens no section
        (
            "In addition, the following additions, removals, and changes have been made to OFAC's list:",
            None,
        ),
        ("In addition, the following names have been added or removed from OFAC's list:", None),
        ("The following is unrelated prose:", None),
    ],
)
def test_section_headers_classify(header: str, action: str | None) -> None:
    assert classify_section_header(header) == action


def test_net_action_prefers_the_strongest_listing_act() -> None:
    assert net_action([ACTION_REMOVAL, ACTION_DESIGNATION]) == ACTION_DESIGNATION
    assert net_action([ACTION_REMOVAL, ACTION_CHANGE]) == ACTION_CHANGE
    assert net_action([ACTION_REMOVAL]) == ACTION_REMOVAL
    assert net_action([]) == ACTION_DESIGNATION


def test_action_date_comes_from_the_url_day() -> None:
    assert action_date_from_link("/recent-actions/20250321", "2025-03-22") == "2025-03-21"
    assert action_date_from_link("/recent-actions/20251119_33", "") == "2025-11-19"
    assert action_date_from_link("/recent-actions/no-day-here", "2024-01-02") == "2024-01-02"
    # a US-format page date is normalised to ISO — dates compare as strings downstream
    assert action_date_from_link("/recent-actions/no-day-here", "3/21/2025") == "2025-03-21"


def test_opensanctions_chain_inference_is_the_shared_shape_rule() -> None:
    """Security audit 2026-09-15 MEDIUM-1: nine OFAC-listed zcash / dash / bitcoin_gold
    addresses landed under the `solana` catch-all; the shared shape rule places them."""
    from openlabels.pipelines.parse_opensanctions import infer_chain

    assert infer_chain("t1MMXtBrSp1XG38Lx9cePcNUCJj5vdWfUWL") == "zcash"
    assert infer_chain("GPwg61XoHqQPNmAucFACuQ5H9sGCDv9TpS") == "bitcoin_gold"
    assert infer_chain("XxLmdAJxAK8yjnuVGVNDGTnf6z6yGHUeFo") == "dash"
    assert infer_chain("31nadacWrgPeAQxKRMabhn3fPhnhi3hjKa") == "bitcoin"
    assert infer_chain("33ee1nuuKyW3id8ER5zM2abQ5D8") is None  # base58 shape, bad checksum
    assert infer_chain(EVM_A) == "ethereum" and infer_chain(TRON_T) == "tron"
    assert infer_chain("") is None


def test_mixed_synthetic_page_by_section() -> None:
    html = _page(
        f"Digital Currency Address - ETH {EVM_D}",  # before any header → designation, no evidence
        "The following individuals have been added to OFAC's SDN List:",
        f"Digital Currency Address - ETH {EVM_A}; alt. Digital Currency Address - ARB {EVM_A}",
        "The following changes have been made to OFAC's SDN List:",
        f"Digital Currency Address - TRX {TRON_T}",
        "The following deletions have been made to OFAC's SDN List:",
        f"Digital Currency Address - ETH {EVM_B}; also mentioned in prose: {EVM_C}",
    )
    out = extract_address_actions(html)
    assert out[EVM_A]["ethereum"]["action"] == ACTION_DESIGNATION
    assert out[EVM_A]["arbitrum"]["action"] == ACTION_DESIGNATION
    assert out[EVM_A]["ethereum"]["action_evidence"] == "section"
    assert out[TRON_T]["tron"]["action"] == ACTION_CHANGE
    assert out[EVM_B]["ethereum"] == {
        "evidence": "ticker",
        "actions": [ACTION_REMOVAL],
        "action": ACTION_REMOVAL,
        "action_evidence": "section",
    }
    assert out[EVM_C]["ethereum"]["evidence"] == "shape"
    assert out[EVM_C]["ethereum"]["action"] == ACTION_REMOVAL
    assert out[EVM_D]["ethereum"] == {
        "evidence": "ticker",
        "actions": [ACTION_DESIGNATION],
        "action": ACTION_DESIGNATION,
        "action_evidence": "none",
    }
    # the chain/evidence projection is exactly the pre-R output
    assert extract_addresses_with_evidence(html) == {
        EVM_A: {("ethereum", "ticker"), ("arbitrum", "ticker")},
        EVM_B: {("ethereum", "ticker")},
        EVM_C: {("ethereum", "shape")},
        EVM_D: {("ethereum", "ticker")},
        TRON_T: {("tron", "ticker")},
    }


def test_same_address_deleted_and_re_added_on_one_page_is_a_designation() -> None:
    html = _page(
        "The following entities have been added to OFAC's SDN List:",
        f"Digital Currency Address - ETH {EVM_A}",
        "The following deletions have been made to OFAC's SDN List:",
        f"Digital Currency Address - ETH {EVM_A}",
    )
    out = extract_address_actions(html)
    assert out[EVM_A]["ethereum"]["actions"] == [ACTION_DESIGNATION, ACTION_REMOVAL]
    assert out[EVM_A]["ethereum"]["action"] == ACTION_DESIGNATION
    action, evidence, sections = page_net_action(out[EVM_A])
    assert (action, evidence, sections) == (
        ACTION_DESIGNATION,
        "section",
        [ACTION_DESIGNATION, ACTION_REMOVAL],
    )


def test_removal_record_asserts_nothing_illicit() -> None:
    html = _page(
        "The following deletions have been made to OFAC's SDN List:",
        f"Digital Currency Address - ETH {EVM_B}",
    )
    out = extract_address_actions(html)
    recs = press_release_records(
        EVM_B,
        out[EVM_B],
        title="Cyber-related Designation Removal",
        source_url="https://ofac.treasury.gov/recent-actions/20250321",
        link="/recent-actions/20250321",
        action_date="2025-03-21",
        page_date="2025-03-21",
        programs=["CYBER2"],
        sanctions_ref="OFAC; CYBER2",
    )
    assert [c for c, _ in recs] == ["ethereum"]
    rec = recs[0][1]
    assert rec["sanctioned"] is False and rec["is_illicit"] is False and rec["category"] is None
    lab = rec["labels"][0]
    assert lab["type"] == "sanctions_removed"
    assert lab["context"] == {
        "source_url": "https://ofac.treasury.gov/recent-actions/20250321",
        "action": ACTION_REMOVAL,
        "action_date": "2025-03-21",
        "action_evidence": "section",
        "sections": [ACTION_REMOVAL],
    }


@pytest.mark.skipif(not _REMOVAL_PAGE.exists(), reason="cached OFAC pages are gitignored")
def test_real_2025_03_21_page_is_a_removal_for_every_tornado_address() -> None:
    out = extract_address_actions(_REMOVAL_PAGE.read_text(encoding="utf-8", errors="replace"))
    assert TORNADO_ROUTER in out
    actions = {slot["action"] for chains in out.values() for slot in chains.values()}
    # the page also carries a "changes" section (North Korea update) — no address is a designation
    assert ACTION_DESIGNATION not in actions
    assert out[TORNADO_ROUTER]["ethereum"]["action"] == ACTION_REMOVAL
    removed = [a for a, chains in out.items() if page_net_action(chains)[0] == ACTION_REMOVAL]
    assert len(removed) >= 90


@pytest.mark.skipif(not _REDESIGNATION_PAGE.exists(), reason="cached OFAC pages are gitignored")
def test_real_2022_11_08_page_keeps_the_re_designated_tornado_addresses_listed() -> None:
    out = extract_address_actions(_REDESIGNATION_PAGE.read_text(encoding="utf-8", errors="replace"))
    slot = out[TORNADO_ROUTER]["ethereum"]
    assert slot["actions"] == [ACTION_DESIGNATION, ACTION_REMOVAL]
    assert slot["action"] == ACTION_DESIGNATION
    assert page_net_action(out[TORNADO_ROUTER])[0] == ACTION_DESIGNATION


@pytest.mark.skipif(not _DESIGNATION_PAGE.exists(), reason="cached OFAC pages are gitignored")
def test_real_2022_08_08_page_is_a_designation() -> None:
    out = extract_address_actions(_DESIGNATION_PAGE.read_text(encoding="utf-8", errors="replace"))
    assert out[TORNADO_ROUTER]["ethereum"]["action"] == ACTION_DESIGNATION
    assert all(
        slot["action"] == ACTION_DESIGNATION for chains in out.values() for slot in chains.values()
    )


def test_base64_fragments_that_look_like_legacy_addresses_are_not_addresses() -> None:
    """Code review 2026-09-15 MEDIUM-2: pre-2018 OFAC pages carry base64 blobs whose substrings
    match the legacy Bitcoin/Litecoin shapes; the checksum tells them apart."""
    junk_btc = "33ee1nuuKyW3id8ER5zM2abQ5D8"  # a real store key, from a 2008-12-29 page
    junk_ltc = "LhQFPzL2EKJ6v3FjVzMbYhTm4gEtmzW2v"  # synthetic, base58 shape, bad checksum
    real_btc = "31nadacWrgPeAQxKRMabhn3fPhnhi3hjKa"  # public OFAC SDN row (P2SH), checksum ok
    real_ltc = "LNf2JDiuunBz7GMDKFYHN4rq5meXWxiwfb"  # public OFAC SDN row (LTC), checksum ok
    html = _page(f"blob {junk_btc} and {junk_ltc}; listed {real_btc} and {real_ltc}")
    out = extract_addresses_with_evidence(html)
    assert junk_btc not in out and junk_ltc not in out
    assert out[real_btc] == {("bitcoin", "shape")}
    assert out[real_ltc] == {("litecoin", "shape")}
    # the ticker path applies the same test: a bad-checksum token under XBT is skipped
    stats: dict[str, int] = {}
    out2 = extract_addresses_with_evidence(
        _page(f"Digital Currency Address - XBT {junk_btc}"), stats
    )
    assert junk_btc not in out2 and stats.get("skipped_shape_mismatch") == 1


# --- R2: OpenSanctions taxonomy -------------------------------------------------------------


@pytest.mark.parametrize(
    ("topics", "datasets", "expected"),
    [
        (["sanction"], ["us_ofac_sdn"], ("sanctioned", None)),
        (["sanction"], ["jp_mof_sanctions"], ("sanctioned", None)),
        ([], ["eu_fsf"], ("sanctioned", None)),
        (["crime.theft"], ["ransomwhere"], ("illicit", "ransomware")),
        (["crime.terror"], ["il_mod_crypto"], ("illicit", "terror_financing")),
        (["crime.fin", "crime.cyber"], ["us_fbi_lazarus_crypto"], ("illicit", "hack")),
        (["crime.fraud"], ["some_new_dataset"], ("illicit", "fraud")),
        ([], ["interpol_red_notices"], ("illicit", "unspecified")),
        ([], ["some_registry"], ("vasp", None)),
    ],
)
def test_classify_wallet_follows_the_source_taxonomy(topics, datasets, expected) -> None:
    assert classify_wallet(topics, datasets) == expected


def _wallet(topics: list[str], datasets: list[str], key: str = EVM_A) -> dict:
    return {
        "id": "test-1",
        "schema": "CryptoWallet",
        "datasets": datasets,
        "first_seen": "2025-01-01",
        "properties": {"publicKey": [key], "topics": topics, "name": ["Example"]},
    }


def test_ransomwhere_row_is_illicit_ransomware_not_sanctioned() -> None:
    (rec,) = process_crypto_wallet(_wallet(["crime.theft"], ["ransomwhere"]), {}, "https://os")
    lab = rec["labels"][0]
    assert lab["type"] == "illicit" and lab["subtype"] == "ransomware"
    assert lab["context"] == {"datasets": ["ransomwhere"], "topics": ["crime.theft"]}
    assert rec["is_illicit"] is True and rec["sanctioned"] is False
    assert rec["category"] is None and rec["sanctions_reference"] is None


def test_ofac_copy_row_stays_sanctioned_with_its_dataset_in_context() -> None:
    (rec,) = process_crypto_wallet(_wallet(["sanction"], ["us_ofac_sdn"]), {}, "https://os")
    lab = rec["labels"][0]
    assert lab["type"] == "sanctioned" and "subtype" not in lab
    assert lab["context"]["datasets"] == ["us_ofac_sdn"]
    assert rec["sanctioned"] is True and rec["category"] == "sanctioned"
    assert rec["sanctions_reference"] == "sanction; us_ofac_sdn"


def test_non_illicit_wallet_keeps_the_historical_vasp_type() -> None:
    (rec,) = process_crypto_wallet(_wallet([], ["some_registry"]), {}, "https://os")
    assert rec["labels"][0]["type"] == "vasp"
    assert rec["is_illicit"] is False and rec["category"] == "unknown"


# --- R3: merge — label key with page identity; record standing from dated labels ------------


def _pr(action: str, day: str, chain: str = "ethereum", name: str = "Cyber-related Designation") -> dict:
    return {
        "name": name,
        "type": "sanctions_removed" if action == ACTION_REMOVAL else "sanctioned",
        "source": "ofac_press_release",
        "chain": chain,
        "context": {
            "source_url": f"https://ofac.treasury.gov/recent-actions/{day.replace('-', '')}",
            "action": action,
            "action_date": day,
            "action_evidence": "section",
            "sections": [action],
        },
    }


def test_label_key_keeps_two_pages_with_the_same_title_and_dedupes_the_same_page() -> None:
    a = _pr(ACTION_DESIGNATION, "2022-08-08")
    b = _pr(ACTION_REMOVAL, "2025-03-21")
    assert len(merge_label_entries([a], [b])) == 2
    assert len(merge_label_entries([a], [dict(a)])) == 1
    legacy = {"name": "X", "type": "sanctioned", "source": "ofac_press_release", "chain": "ethereum"}
    assert len(merge_label_entries([legacy], [dict(legacy)])) == 1


def _record(labels: list[dict], **fields) -> dict:
    rec = {
        "address": EVM_A,
        "chain": "ethereum",
        "labels": labels,
        "is_illicit": True,
        "sanctioned": True,
        "category": "sanctioned",
    }
    rec.update(fields)
    return rec


def test_add_then_removal_ends_the_listing() -> None:
    rec = _record([_pr(ACTION_DESIGNATION, "2022-08-08"), _pr(ACTION_REMOVAL, "2025-03-21")])
    assert press_release_status(rec["labels"]) == "removed"
    assert reconcile_press_release_status(rec) is True
    assert rec["sanctioned"] is False and rec["is_illicit"] is False and rec["category"] is None
    assert reconcile_press_release_status(rec) is False  # idempotent


def test_add_removal_add_is_listed_again() -> None:
    rec = _record(
        [
            _pr(ACTION_DESIGNATION, "2022-08-08"),
            _pr(ACTION_REMOVAL, "2022-11-08"),
            _pr(ACTION_DESIGNATION, "2022-11-08"),  # re-designated the same day
        ],
        sanctioned=False,
        is_illicit=False,
        category=None,
    )
    assert press_release_status(rec["labels"]) == "listed"
    assert reconcile_press_release_status(rec) is True
    assert rec["sanctioned"] is True and rec["is_illicit"] is True and rec["category"] == "sanctioned"


def test_labels_without_context_do_not_vote() -> None:
    legacy = {"name": "X", "type": "sanctioned", "source": "ofac_press_release", "chain": "ethereum"}
    rec = _record([legacy])
    assert press_release_status(rec["labels"]) is None
    assert reconcile_press_release_status(rec) is False
    assert rec["sanctioned"] is True


def test_another_sources_sanction_keeps_the_record_sanctioned_after_an_ofac_removal() -> None:
    other = {"name": "Lazarus Group", "type": "sanctioned", "source": "opensanctions", "chain": "ethereum"}
    rec = _record([_pr(ACTION_DESIGNATION, "2022-08-08"), _pr(ACTION_REMOVAL, "2025-03-21"), other])
    assert reconcile_press_release_status(rec) is False
    assert rec["sanctioned"] is True and rec["category"] == "sanctioned"


def test_removal_keeps_is_illicit_when_another_label_claims_it() -> None:
    mixer = {
        "name": "Tornado.Cash",
        "type": "illicit",
        "subtype": "tornado-cash",
        "source": "tornado_interactors",
        "chain": "ethereum",
    }
    rec = _record([_pr(ACTION_DESIGNATION, "2022-08-08"), _pr(ACTION_REMOVAL, "2025-03-21"), mixer])
    assert reconcile_press_release_status(rec) is True
    assert rec["sanctioned"] is False and rec["category"] is None
    assert rec["is_illicit"] is True  # the other source's claim stands
    rekt = {"name": "Some exploit", "type": "other", "source": "crypto_rekts", "chain": "ethereum"}
    rec2 = _record([_pr(ACTION_REMOVAL, "2025-03-21"), rekt])
    reconcile_press_release_status(rec2)
    assert rec2["is_illicit"] is True  # crypto_rekts files exploits under `other`


def test_merge_records_or_is_corrected_by_the_reconciliation() -> None:
    base = _record([_pr(ACTION_DESIGNATION, "2022-08-08")])
    incoming = {
        "address": EVM_A,
        "chain": "ethereum",
        "labels": [_pr(ACTION_REMOVAL, "2025-03-21")],
        "is_illicit": False,
        "sanctioned": False,
        "category": None,
    }
    merged = merge_records(base, incoming)
    assert merged["sanctioned"] is True  # the OR keeps it — the reconciliation must run after
    assert reconcile_press_release_status(merged) is True
    assert merged["sanctioned"] is False and len(merged["labels"]) == 2
