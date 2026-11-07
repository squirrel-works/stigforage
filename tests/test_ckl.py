"""CKL import/export tests. Fixtures: MIT-licensed stig-manager-client-modules test files."""

from __future__ import annotations

import itertools
import json
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import FIXTURES, ORACLE_SCHEMA_DEVIATIONS, VOLATILE, rules_without, stig_header
from stigforage import ckl, cklb
from stigforage.model import ChecklistError, Status
from stigforage.xmlsafe import UnsafeXmlError

CKL_DIR = FIXTURES / "ckl"
VPN = CKL_DIR / "Asset_a-VPN_TRUNCATED-V2R5.ckl"
ORACLE = CKL_DIR / "Asset_a-VPN_TRUNCATED-V2R5.oracle.cklb"
# Loadable fixtures. The rest are deliberately broken and covered by failure-path tests below.
GOOD = ["Asset_a-VPN_TRUNCATED-V2R5.ckl", "Asset_a-multi-stig.ckl", "MultiStig-Simple.ckl",
        "Single-Vuln-fail-with-Comment.ckl", "html-decode.ckl"]  # fmt: skip


def test_matches_independent_cklb_for_same_asset(id_factory: Callable[[], str]) -> None:
    """The oracle CKLB was produced by STIG Manager from the same asset data."""
    mine = cklb.to_dict(ckl.load(VPN, new_id=id_factory).checklist)
    oracle = json.loads(ORACLE.read_text("utf-8-sig"))
    assert mine["target_data"] == oracle["target_data"]
    # Known, deliberate differences: stig_ref is carried from the CKL's STIGRef (the oracle has
    # null), the review text in the two fixture files was edited independently, and the oracle's
    # null text fields are "" here because the DISA schema forbids null.
    ignore = {"stig_ref", "finding_details", "comments"} | ORACLE_SCHEMA_DEVIATIONS
    assert rules_without(mine, VOLATILE | ignore) == rules_without(oracle, VOLATILE | ignore)
    assert stig_header(mine) == stig_header(oracle)


def test_status_mapping_and_review_text(id_factory: Callable[[], str]) -> None:
    rules = ckl.load(VPN, new_id=id_factory).checklist.stigs[0].rules
    assert {r.status for r in rules} == set(Status)
    assert rules[0].group_id == "V-207184"
    assert rules[0].rule_id == "SV-207184r695317"
    assert rules[0].rule_id_src == "SV-207184r695317_rule"
    assert rules[0].ccis == ["CCI-001414"]


def test_multi_stig_file() -> None:
    result = ckl.load(CKL_DIR / "Asset_a-multi-stig.ckl")
    assert [s.stig_id for s in result.checklist.stigs] == [
        "RHEL_8_TRUNCATED", "RHEL_9_TRUNCATED", "VPN_TRUNCATED",
    ]  # fmt: skip
    assert result.checklist.stigs[0].extra["size"] == 10


def test_xml_entities_and_char_refs_are_decoded_exactly_once() -> None:
    rule = ckl.load(CKL_DIR / "html-decode.ckl").checklist.stigs[0].rules[0]
    # Source holds &amp; &lt; &gt; &quot; &#039; &#x26; &#60; ... and numeric refs like &#65;.
    assert rule.finding_details == "& < > \" ' & < & < > \" ' A . % , ~"


@pytest.mark.parametrize("name", GOOD)
def test_ckl_to_cklb_to_ckl_round_trip_keeps_rules(name: str) -> None:
    ids = itertools.count()
    first = ckl.load(CKL_DIR / name, new_id=lambda: f"i{next(ids)}").checklist
    xml_text, warnings = ckl.dumps(first)
    assert warnings == []
    ids2 = itertools.count()
    second = ckl.loads(xml_text.encode(), new_id=lambda: f"i{next(ids2)}").checklist
    assert cklb.to_dict(first) == cklb.to_dict(second)


def test_cklb_to_ckl_to_cklb_keeps_review_state() -> None:
    original = cklb.load(FIXTURES / "cklb" / "Asset_a-multi-stig.cklb")
    xml_text, _ = ckl.dumps(original)
    again = ckl.loads(xml_text.encode()).checklist
    for a, b in zip(original.stigs, again.stigs, strict=True):
        assert [(r.group_id, r.rule_id, r.status, r.ccis) for r in a.rules] == [
            (r.group_id, r.rule_id, r.status, r.ccis) for r in b.rules
        ]
        assert [(r.comments or "", r.finding_details or "") for r in a.rules] == [
            (r.comments or "", r.finding_details or "") for r in b.rules
        ]


# --- failure paths --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "match"),
    [
        ("No-Asset-xml-element.ckl", "missing ASSET"),
        ("no-Status-xml-element.ckl", r"STATUS: '' is not one of"),
        ("no-checklist-xml-element.ckl", "expected 'CHECKLIST'"),
        ("no-SID_DATA-element.ckl", "missing SI_DATA 'stigid'"),
        ("all-possible-results.ckl", "invalid XML at line 255"),  # genuinely malformed fixture
    ],
)
def test_broken_fixtures_fail_loudly(name: str, match: str) -> None:
    with pytest.raises(ChecklistError, match=match):
        ckl.load(CKL_DIR / name)


def _ckl(vuln_extra: str = "", status: str = "Open", asset_extra: str = "") -> bytes:
    return f"""<CHECKLIST><ASSET><HOST_NAME>h</HOST_NAME>{asset_extra}</ASSET><STIGS><iSTIG>
<STIG_INFO><SI_DATA><SID_NAME>stigid</SID_NAME><SID_DATA>S</SID_DATA></SI_DATA>
<SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>T</SID_DATA></SI_DATA></STIG_INFO>
<VULN>
<STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA>
<STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>low</ATTRIBUTE_DATA></STIG_DATA>
<STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-1r1_rule</ATTRIBUTE_DATA></STIG_DATA>
<STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>X-1</ATTRIBUTE_DATA></STIG_DATA>
{vuln_extra}<STATUS>{status}</STATUS></VULN></iSTIG></STIGS></CHECKLIST>""".encode()


def test_minimal_ckl_loads() -> None:
    result = ckl.loads(_ckl())
    rule = result.checklist.stigs[0].rules[0]
    assert (rule.group_id, rule.rule_id, rule.severity, rule.status) == (
        "V-1", "SV-1r1", "low", Status.OPEN,
    )  # fmt: skip
    assert result.warnings == []


def test_unknown_status_value() -> None:
    with pytest.raises(ChecklistError, match=r"STATUS: 'Passed' is not one of"):
        ckl.loads(_ckl(status="Passed"))


@pytest.mark.parametrize("attr", ["Vuln_Num", "Severity", "Rule_ID", "Rule_Ver"])
def test_missing_required_attribute(attr: str) -> None:
    data = _ckl().decode()
    start = data.index(f"<VULN_ATTRIBUTE>{attr}<")
    begin = data.rindex("<STIG_DATA>", 0, start)
    end = data.index("</STIG_DATA>", start) + len("</STIG_DATA>")
    with pytest.raises(ChecklistError, match=f"STIG_DATA '{attr}'"):
        ckl.loads((data[:begin] + data[end:]).encode())


def test_severity_override_is_reported_not_dropped_silently() -> None:
    data = _ckl().replace(b"</VULN>", b"<SEVERITY_OVERRIDE>high</SEVERITY_OVERRIDE></VULN>")
    result = ckl.loads(data)
    assert any("severity override not carried over" in w for w in result.warnings)


def test_unrecognised_attribute_and_marking_are_reported() -> None:
    extra = (
        "<STIG_DATA><VULN_ATTRIBUTE>Weird_Thing</VULN_ATTRIBUTE>"
        "<ATTRIBUTE_DATA>x</ATTRIBUTE_DATA></STIG_DATA>"
    )
    result = ckl.loads(_ckl(extra, asset_extra="<MARKING>CUI</MARKING>"))
    assert any("'Weird_Thing'" in w for w in result.warnings)
    assert any("MARKING 'CUI'" in w for w in result.warnings)


def test_multiple_cci_and_legacy_ids() -> None:
    extra = "".join(
        f"<STIG_DATA><VULN_ATTRIBUTE>{n}</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{v}</ATTRIBUTE_DATA></STIG_DATA>"
        for n, v in [("CCI_REF", "CCI-000001"), ("CCI_REF", "CCI-000002"), ("LEGACY_ID", "V-9")]
    )
    rule = ckl.loads(_ckl(extra)).checklist.stigs[0].rules[0]
    assert rule.ccis == ["CCI-000001", "CCI-000002"]
    assert rule.extra["legacy_ids"] == ["V-9"]


def test_doctype_in_ckl_is_refused() -> None:
    evil = b'<!DOCTYPE CHECKLIST [<!ENTITY x "y">]>' + _ckl()
    with pytest.raises(UnsafeXmlError):
        ckl.loads(evil)


# --- writing --------------------------------------------------------------------------------


def test_written_xml_is_well_formed_and_escapes_markup() -> None:
    checklist = cklb.load(FIXTURES / "cklb" / "Asset_a-VPN_TRUNCATED-V2R5.cklb")
    checklist.stigs[0].rules[0].comments = "a <b> & \"c\" 'd'"
    text, _ = ckl.dumps(checklist)
    root = ET.fromstring(text)
    assert root.tag == "CHECKLIST"
    assert text.startswith('<?xml version="1.0" encoding="UTF-8"?>\n')
    reread = ckl.loads(text.encode()).checklist
    assert reread.stigs[0].rules[0].comments == "a <b> & \"c\" 'd'"


def test_control_characters_are_stripped_with_a_warning() -> None:
    checklist = cklb.load(FIXTURES / "cklb" / "Asset_a-VPN_TRUNCATED-V2R5.cklb")
    checklist.stigs[0].rules[0].comments = "bad\x00char"
    text, warnings = ckl.dumps(checklist)
    assert "\x00" not in text
    assert any("control characters" in w for w in warnings)
    ckl.loads(text.encode())  # must still be readable


def test_overrides_produce_a_warning_on_export() -> None:
    checklist = cklb.load(FIXTURES / "cklb" / "Asset_a-VPN_TRUNCATED-V2R5.cklb")
    checklist.stigs[0].rules[0].overrides = {"severity": {"severity": "high"}}
    _, warnings = ckl.dumps(checklist)
    assert any("overrides not written" in w for w in warnings)


def test_dump_refuses_overwrite_and_force_works(tmp_path: Path) -> None:
    checklist = cklb.load(FIXTURES / "cklb" / "Asset_a-VPN_TRUNCATED-V2R5.cklb")
    dest = tmp_path / "out.ckl"
    dest.write_text("precious", encoding="utf-8")
    with pytest.raises(FileExistsError, match="--force"):
        ckl.dump(checklist, dest)
    assert dest.read_text(encoding="utf-8") == "precious"
    ckl.dump(checklist, dest, force=True)
    assert ckl.load(dest).checklist.stigs[0].stig_id == checklist.stigs[0].stig_id
    assert [p.name for p in tmp_path.iterdir()] == ["out.ckl"]
