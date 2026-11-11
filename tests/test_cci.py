"""CCI to NIST SP 800-53 Revision 5 crosswalk (ADR 0005, unit 1).

Two kinds of test. The crosswalk's rules run everywhere, CI included, against a small synthetic
list built here. Checks against DISA's real CCI list (version 2025-01-23) run only where it
has been downloaded to tests/fixtures/local/ for local testing; it is never committed, and the
`disa_cci_list` fixture skips with the download command when it is absent.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from conftest import DISA_CCI_ZIP, FIXTURES
from stigforage import cklb
from stigforage.cci import CciList, crosswalk, load_cci_list, loads_cci_list, parse_reference
from stigforage.model import ChecklistError

MULTI = FIXTURES / "cklb" / "Asset_a-multi-stig.cklb"
RHEL9 = FIXTURES / "xccdf-results" / "RHEL_9-V2R10-manual-truncated.cklb"
NS = "http://iase.disa.mil/cci"


def _xml(*items: str, root: str = "cci_list") -> bytes:
    body = "".join(items)
    return (
        f'<{root} xmlns="{NS}"><metadata><version>test</version></metadata>'
        f"<cci_items>{body}</cci_items></{root}>"
    ).encode()


def _item(cci: str, *refs: tuple[str, str], status: str = "draft") -> str:
    xml_refs = "".join(f'<reference version="{v}" index="{ix}"/>' for v, ix in refs)
    return f'<cci_item id="{cci}"><status>{status}</status><references>{xml_refs}</references></cci_item>'


# The shapes DISA's real list uses (ADR 0005), in a list small enough to read.
SYNTHETIC = _xml(
    _item("CCI-000366", ("4", "CM-6 b"), ("5", "CM-6 b")),
    _item("CCI-000015", ("5", "AC-2 (1)")),
    _item("CCI-002132", ("4", "AC-2 (4)")),  # Revision 4 only: unmapped for Revision 5
    _item("CCI-003658", ("5", "SA-11 (6)"), status="deprecated"),
    _item("CCI-000213", ("5", "AC-3"), ("5", "AC-3 (2)")),  # two references
)


@pytest.fixture
def cci_list() -> CciList:
    return loads_cci_list(SYNTHETIC, source="synthetic")


# --- reading a list -------------------------------------------------------------------------


def test_list_version_and_entries(cci_list: CciList) -> None:
    assert (cci_list.version, len(cci_list.entries)) == ("test", 5)
    [ref] = cci_list.entries["CCI-000366"].rev5
    assert (ref.reference, ref.control, ref.family) == ("CM-6 b", "CM-6", "CM")
    assert cci_list.entries["CCI-003658"].deprecated


def test_only_revision_5_references_are_kept(cci_list: CciList) -> None:
    assert [r.reference for r in cci_list.entries["CCI-000366"].rev5] == ["CM-6 b"]
    assert cci_list.entries["CCI-002132"].rev5 == ()


def test_list_loads_from_a_zip_or_bare_xml(tmp_path: Path, cci_list: CciList) -> None:
    xml = tmp_path / "U_CCI_List.xml"
    xml.write_bytes(SYNTHETIC)
    packed = tmp_path / "U_CCI_List.zip"
    with zipfile.ZipFile(packed, "w") as zf:
        zf.writestr("README.TXT", "DISA's zip also holds HTML and XSL files")
        zf.writestr("U_CCI_List.html", "<html/>")
        zf.writestr("U_CCI_List.xml", SYNTHETIC)
    assert load_cci_list(xml).entries == load_cci_list(packed).entries == cci_list.entries


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (_xml(_item("CCI-1"), root="something_else"), "is not DISA's cci_list"),
        (_xml(), "no cci_item elements"),
        (_xml("<cci_item><status>draft</status></cci_item>"), "has no id"),
        (_xml(_item("CCI-1", ("5", "not a control"))), "is not a NIST control"),
        (b"<!DOCTYPE x [<!ENTITY a 'b'>]><cci_list/>", "DTD or entity declarations"),
    ],
)
def test_malformed_lists_are_refused(data: bytes, message: str) -> None:
    with pytest.raises(ChecklistError, match=message):
        loads_cci_list(data)


def test_a_zip_without_the_list_is_refused(tmp_path: Path) -> None:
    empty = tmp_path / "other.zip"
    with zipfile.ZipFile(empty, "w") as zf:
        zf.writestr("README.TXT", "no list here")
    with pytest.raises(ChecklistError, match=r"expected one U_CCI_List.xml"):
        load_cci_list(empty)
    broken = tmp_path / "broken.zip"
    broken.write_bytes(b"not a zip")
    with pytest.raises(ChecklistError, match="not a valid ZIP file"):
        load_cci_list(broken)


# --- references to controls -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("reference", "control"),
    [
        ("AC-2", "AC-2"),
        ("AC-2 e", "AC-2"),  # a part
        ("AC-1 c 1", "AC-1"),
        ("AC-1 a 1 (a)", "AC-1"),
        ("AC-2 (4)", "AC-2(4)"),  # an enhancement is its own control
        ("AC-2 (3) (d)", "AC-2(3)"),
        ("IA-5 (2) (b) (1)", "IA-5(2)"),
        ("CP-9 (a)", "CP-9"),  # DISA's parenthesised part letter, not an enhancement
        ("SC-7 (4) (h)", "SC-7(4)"),
    ],
)
def test_reference_forms_seen_in_disas_list(reference: str, control: str) -> None:
    ref = parse_reference(reference)
    assert (ref.reference, ref.control, ref.family) == (reference, control, reference[:2])


# --- crosswalk ------------------------------------------------------------------------------


def test_crosswalk_reports_every_cci_that_does_not_map(cci_list: CciList) -> None:
    result = crosswalk(
        ["CCI-000366", "CCI-002132", "CCI-999999", "CCI-003658", "CCI-000366"], cci_list
    )
    assert result.unmapped == ["CCI-002132"]  # in the list, no Revision 5 reference
    assert result.unknown == ["CCI-999999"]  # not in the list
    assert result.deprecated == ["CCI-003658"]  # mapped, but retired by DISA
    assert result.controls == ["CM-6", "SA-11(6)"]  # CCI-000366 listed twice, counted once


def test_a_cci_listed_twice_is_reported_once(cci_list: CciList) -> None:
    result = crosswalk(["CCI-002132", "CCI-999999", "CCI-002132", "CCI-999999"], cci_list)
    assert (result.unmapped, result.unknown) == (["CCI-002132"], ["CCI-999999"])


def test_crosswalk_keeps_every_reference_of_a_cci(cci_list: CciList) -> None:
    result = crosswalk(["CCI-000213", "CCI-000015"], cci_list)
    assert [r.reference for r in result.references] == ["AC-3", "AC-3 (2)", "AC-2 (1)"]
    assert result.controls == ["AC-3", "AC-3(2)", "AC-2(1)"]


def test_no_ccis_means_an_empty_crosswalk(cci_list: CciList) -> None:
    result = crosswalk([], cci_list)
    assert (result.references, result.unmapped, result.unknown, result.deprecated) == (
        [],
        [],
        [],
        [],
    )


# --- DISA's real list (local only) ----------------------------------------------------------


def test_real_cci_list_counts(disa_cci_list: CciList) -> None:
    assert disa_cci_list.version == "2025-01-23"
    assert len(disa_cci_list.entries) == 5137
    assert sum(1 for e in disa_cci_list.entries.values() if e.rev5) == 3836
    assert sum(1 for e in disa_cci_list.entries.values() if e.deprecated) == 91
    # Every Revision 5 reference parsed (loading raises otherwise); 3,838 across 3,836 CCIs.
    assert sum(len(e.rev5) for e in disa_cci_list.entries.values()) == 3838
    assert {e.cci for e in disa_cci_list.entries.values() if e.deprecated and e.rev5} == {
        "CCI-003658",
        "CCI-004692",
    }


def test_real_cci_list_loads_from_the_bare_xml(tmp_path: Path, disa_cci_list: CciList) -> None:
    xml = tmp_path / "U_CCI_List.xml"
    with zipfile.ZipFile(DISA_CCI_ZIP) as zf:
        xml.write_bytes(zf.read("U_CCI_List.xml"))
    assert load_cci_list(xml).entries == disa_cci_list.entries


def test_real_list_against_the_fixture_checklists(disa_cci_list: CciList) -> None:
    # The truncated RHEL 9 V1R1 STIG in the multi-STIG fixture uses CCI-001233, which has no
    # Revision 5 reference; every other fixture CCI maps.
    unmapped = {
        cci
        for stig in cklb.load(MULTI).stigs
        for rule in stig.rules
        for cci in crosswalk(rule.ccis, disa_cci_list).unmapped
    }
    assert unmapped == {"CCI-001233"}
    rhel9 = cklb.load(RHEL9).stigs[0]
    controls = {c for rule in rhel9.rules for c in crosswalk(rule.ccis, disa_cci_list).controls}
    assert controls and all(c[:2].isalpha() and c[2] == "-" for c in controls)
