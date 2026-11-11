"""`export csv` and the shared row flattening (ADR 0005 decisions 4 and 5, unit 2)."""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest

from conftest import DISA_CCI_ZIP, FIXTURES, SYNTHETIC_CCI_XML
from stigforage import cklb
from stigforage.cci import CciList
from stigforage.cli import EXIT_OK, EXIT_UNREADABLE, run
from stigforage.exports import CSV_COLUMNS, cat, finding_rows, release_label, to_csv
from stigforage.model import Checklist, Rule, Status, Stig

MULTI_A = FIXTURES / "cklb" / "Asset_a-multi-stig.cklb"
MULTI_B = FIXTURES / "cklb" / "Asset_b-multi-stig.cklb"
RHEL9 = FIXTURES / "xccdf-results" / "RHEL_9-V2R10-manual-truncated.cklb"


def _rule(group: str = "V-1", **kw: object) -> Rule:
    base: dict[str, object] = {
        "group_id": group,
        "rule_id": f"S{group}r1",
        "rule_version": "X-1",
        "severity": "medium",
        "status": Status.OPEN,
        "rule_title": "title",
    }
    return Rule(**{**base, **kw})  # type: ignore[arg-type]


def _checklist(*rules: Rule, host: str = "h1") -> Checklist:
    stig = Stig("n", "n", "S", "Release: 3", list(rules), version=1)
    return Checklist("t", "i", {"host_name": host}, [stig])


def _read(text: str) -> list[dict[str, str]]:
    assert text.startswith("﻿")
    return list(csv.DictReader(io.StringIO(text[1:], newline="")))


def _cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return run(list(argv), out=out), out.getvalue()


# --- rows -----------------------------------------------------------------------------------


def test_one_row_per_rule_per_stig_per_checklist_in_input_order() -> None:
    a, b = cklb.load(MULTI_A), cklb.load(MULTI_B)
    rows, _ = finding_rows([a, b], None)
    assert len(rows) == sum(len(s.rules) for c in (a, b) for s in c.stigs) == 60
    assert [r.host for r in rows[:30]] == [a.host_name] * 30
    assert [r.host for r in rows[30:]] == [b.host_name] * 30
    assert [r.group_id for r in rows[:10]] == [r.group_id for r in a.stigs[0].rules]


def test_release_labels_from_real_fixtures() -> None:
    labels = {s.stig_id: release_label(s) for s in cklb.load(MULTI_A).stigs}
    assert labels == {
        "RHEL_8_TRUNCATED": "V1R12",
        "RHEL_9_TRUNCATED": "V1R1",
        "VPN_TRUNCATED": "V2R5",
    }
    # Schema-valid CKLB carries no STIG version, so only the release is known.
    assert release_label(cklb.load(RHEL9).stigs[0]) == "V?R10"


def test_unrecognised_release_info_is_kept_as_written() -> None:
    stig = Stig("n", "n", "S", "  Draft, no release yet ", [], version=None)
    assert release_label(stig) == "Draft, no release yet"


@pytest.mark.parametrize(
    ("severity", "category"), [("high", "I"), ("medium", "II"), ("low", "III"), ("unknown", "")]
)
def test_cat(severity: str, category: str) -> None:
    assert cat(severity) == category


def test_crosswalk_columns_and_notes(synthetic_cci_list: CciList) -> None:
    checklist = _checklist(
        _rule("V-1", ccis=["CCI-000366", "CCI-000366"]),  # listed twice: one CCI
        _rule("V-2", ccis=["CCI-002132"]),  # no Revision 5 reference
        _rule("V-3", ccis=["CCI-999999"]),  # not in the list
        _rule("V-4", ccis=["CCI-003658"]),  # deprecated, still mapped
        _rule("V-5", ccis=["CCI-000213"]),  # two references
    )
    rows, summary = finding_rows([checklist], synthetic_cci_list)
    by = {r.group_id: r for r in rows}
    assert (by["V-1"].ccis, by["V-1"].controls, by["V-1"].references) == (
        ("CCI-000366",),
        ("CM-6",),
        ("CM-6 b",),
    )
    assert (by["V-2"].controls, by["V-2"].notes) == ((), ("CCI-002132: no Rev 5 reference",))
    assert by["V-3"].notes == ("CCI-999999: not in the CCI list",)
    assert (by["V-4"].controls, by["V-4"].notes) == (("SA-11(6)",), ("CCI-003658: deprecated",))
    assert by["V-5"].controls == ("AC-3", "AC-3(2)")
    assert (summary.applied, summary.cci_list_version) == (True, "test")
    assert (summary.cci_refs, summary.mapped) == (5, 3)
    assert (summary.unmapped, summary.unknown, summary.deprecated) == (
        {"CCI-002132"},
        {"CCI-999999"},
        {"CCI-003658"},
    )


def test_without_a_cci_list_the_crosswalk_columns_are_empty() -> None:
    rows, summary = finding_rows([_checklist(_rule(ccis=["CCI-000366"]))], None)
    assert (rows[0].controls, rows[0].references, rows[0].notes) == ((), (), ())
    assert not summary.applied


# --- CSV ------------------------------------------------------------------------------------


def test_csv_has_a_bom_crlf_lines_and_reads_back(synthetic_cci_list: CciList) -> None:
    rows, _ = finding_rows([cklb.load(MULTI_A)], synthetic_cci_list)
    text = to_csv(rows)
    assert text.startswith("﻿Host,STIG,Release,")
    assert "\r\n" in text and "\n" not in text.replace("\r\n", "")
    read = _read(text)
    assert tuple(read[0]) == CSV_COLUMNS
    assert len(read) == len(rows)
    first = read[0]
    assert (first["Host"], first["STIG"], first["Status"]) == (
        rows[0].host,
        rows[0].stig_id,
        "Not Reviewed",
    )


@pytest.mark.parametrize("value", ["=1+1", "+cmd|' /C calc'!A0", "-2", "@SUM(1)", "\tx", "\rx"])
def test_cells_excel_would_run_as_formulas_are_neutralised(value: str) -> None:
    text = to_csv(finding_rows([_checklist(_rule(comments=value, rule_title=value))], None)[0])
    [row] = _read(text)
    assert row["Comments"] == row["Rule Title"] == f"'{value}"


@pytest.mark.parametrize("value", ["plain text", "a=b", "1-2", "e@mail"])
def test_ordinary_text_is_left_alone(value: str) -> None:
    [row] = _read(to_csv(finding_rows([_checklist(_rule(comments=value))], None)[0]))
    assert row["Comments"] == value


def test_multiline_and_non_ascii_text_survive() -> None:
    details = 'line one\nline two, with "quotes" and a comma\nÉtat: échoué ✓'
    [row] = _read(to_csv(finding_rows([_checklist(_rule(finding_details=details))], None)[0]))
    assert row["Finding Details"] == details


def test_statuses_are_written_as_words() -> None:
    statuses = [Status.OPEN, Status.NOT_A_FINDING, Status.NOT_APPLICABLE, Status.NOT_REVIEWED]
    checklist = _checklist(*(_rule(f"V-{i}", status=s) for i, s in enumerate(statuses)))
    read = _read(to_csv(finding_rows([checklist], None)[0]))
    assert [r["Status"] for r in read] == [
        "Open",
        "Not a Finding",
        "Not Applicable",
        "Not Reviewed",
    ]


# --- CLI ------------------------------------------------------------------------------------


def test_cli_export_csv_is_a_dry_run_by_default(tmp_path: Path) -> None:
    dest = tmp_path / "out.csv"
    code, out = _cli("export", "csv", str(MULTI_A), "-o", str(dest))
    assert code == EXIT_OK
    assert "no --cci-list given: the NIST 800-53 Rev 5 columns are left empty" in out
    assert "dry run: would write 30 row(s) from 1 checklist(s)" in out
    assert not dest.exists()


def test_cli_export_csv_writes_with_a_cci_list(tmp_path: Path) -> None:
    cci = tmp_path / "U_CCI_List.xml"
    cci.write_bytes(SYNTHETIC_CCI_XML)
    dest = tmp_path / "out.csv"
    code, out = _cli("export", "csv", str(MULTI_A), str(MULTI_B), "--cci-list", str(cci),
                     "-o", str(dest), "--apply")  # fmt: skip
    assert code == EXIT_OK
    assert "Rev 5 crosswalk (CCI list test):" in out
    assert "wrote 60 row(s) from 2 checklist(s)" in out
    data = dest.read_bytes()
    assert data.startswith(b"\xef\xbb\xbf")
    read = _read(data.decode("utf-8"))
    assert any(r["NIST 800-53 Rev 5 Controls"] == "CM-6" for r in read)


def test_cli_export_csv_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    dest = tmp_path / "out.csv"
    dest.write_text("precious", "utf-8")
    for apply in ([], ["--apply"]):
        assert _cli("export", "csv", str(MULTI_A), "-o", str(dest), *apply)[0] == EXIT_UNREADABLE
    assert dest.read_text("utf-8") == "precious"
    assert _cli("export", "csv", str(MULTI_A), "-o", str(dest), "--apply", "--force")[0] == EXIT_OK
    assert dest.read_text("utf-8-sig").startswith("Host,")


@pytest.mark.parametrize("name", ["out.xlsx", "out.cklb", "out"])
def test_cli_export_csv_needs_a_csv_path(tmp_path: Path, name: str) -> None:
    assert _cli("export", "csv", str(MULTI_A), "-o", str(tmp_path / name))[0] == EXIT_UNREADABLE


def test_cli_export_refuses_to_overwrite_an_input(tmp_path: Path) -> None:
    cci = tmp_path / "cci.csv"  # a CCI list path that happens to end in .csv
    cci.write_bytes(SYNTHETIC_CCI_XML)
    code, _ = _cli("export", "csv", str(MULTI_A), "--cci-list", str(cci), "-o", str(cci), "--force")
    assert code == EXIT_UNREADABLE
    assert cci.read_bytes() == SYNTHETIC_CCI_XML


def test_cli_export_unreadable_inputs_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = str(tmp_path / "o.csv")
    assert _cli("export", "csv", str(tmp_path / "missing.cklb"), "-o", dest)[0] == EXIT_UNREADABLE
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    code, _ = _cli("export", "csv", str(MULTI_A), "--cci-list", str(bad), "-o", dest)
    assert code == EXIT_UNREADABLE
    assert "cannot read CCI list" in capsys.readouterr().err


def test_cli_export_with_disas_real_cci_list(tmp_path: Path, disa_cci_list: CciList) -> None:
    # Local only: skips when the CCI list has not been downloaded (as in CI).
    dest = tmp_path / "out.csv"
    code, out = _cli("export", "csv", str(MULTI_A), "--cci-list", str(DISA_CCI_ZIP),
                     "-o", str(dest), "--apply")  # fmt: skip
    assert code == EXIT_OK
    assert f"(CCI list {disa_cci_list.version}): 41 of 42 CCI references mapped" in out
    read = _read(dest.read_text("utf-8"))
    notes = {r["Rev 5 Crosswalk Notes"] for r in read if r["Rev 5 Crosswalk Notes"]}
    assert notes == {"CCI-001233: no Rev 5 reference"}
