"""`fetch_ofac_primary --from-dir` parses a pinned XML snapshot instead of
downloading: the manifest must carry the sha256 of the given files, and the
parser must read the entity-scoped layout (featureTypeId on the <type> child).
The fixture is synthetic: an invented entity id and a Tron address built from
twenty zero bytes — nobody's address, carried under the "XBT" ticker exactly as
OFAC files SDN-45404 (the case behind graphsense-tagpacks#53).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from openlabels.pipelines.fetch_ofac_primary import parse
from openlabels.tron_address import hex_to_base58check

ZERO_T = hex_to_base58check("0x" + "00" * 20)

_XML = """<?xml version="1.0" encoding="utf-8"?>
<sanctionsData xmlns="https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML">
  <entities>
    <entity id="900001">
      <sanctionsPrograms><sanctionsProgram>CYBER2</sanctionsProgram></sanctionsPrograms>
      <names><name><translations><translation>
        <formattedFullName>EXAMPLE ENTITY ONE</formattedFullName>
      </translation></translations></name></names>
      <features>
        <feature id="1"><type featureTypeId="344">Digital Currency Address - XBT</type><value>{zero_t}</value></feature>
        <feature id="2"><type featureTypeId="1">Website</type><value>example.invalid</value></feature>
      </features>
    </entity>
  </entities>
</sanctionsData>
"""


def _write_snapshot(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "sdn_enhanced.xml").write_text(_XML.format(zero_t=ZERO_T))
    (d / "cons_enhanced.xml").write_text(_XML.replace("900001", "900002").format(zero_t=ZERO_T))


def test_parse_reads_entity_scoped_features(tmp_path: Path) -> None:
    _write_snapshot(tmp_path)
    rows = parse(tmp_path / "sdn_enhanced.xml")
    assert rows == [{"address": ZERO_T, "currency": "XBT", "entity_name": "EXAMPLE ENTITY ONE",
                     "entity_id": "900001", "programs": ["CYBER2"]}]


def test_from_dir_skips_download_and_pins_sha(tmp_path: Path) -> None:
    snap = tmp_path / "snap"
    _write_snapshot(snap)
    out = tmp_path / "out"
    r = subprocess.run(
        [sys.executable, "-m", "openlabels.pipelines.fetch_ofac_primary",
         "--out", str(out), "--from-dir", str(snap), "--min-addresses", "1"],
        capture_output=True, text=True, timeout=120,
    )
    assert r.returncode == 0, r.stderr
    manifest = json.loads((out / "manifest.json").read_text())
    for name in ("sdn_enhanced", "cons_enhanced"):
        expected = hashlib.sha256((snap / f"{name}.xml").read_bytes()).hexdigest()
        assert manifest["sources"][name]["sha256"] == expected
        assert manifest["sources"][name]["local_file"] == str(snap / f"{name}.xml")
        assert (snap / f"{name}.xml").exists()  # pinned input is never deleted
    wallets = json.loads((out / "ofac_wallets.json").read_text())
    assert [w["address"] for w in wallets] == [ZERO_T]  # (address, currency) de-duplicated
    assert manifest["by_currency"] == {"XBT": 1}
