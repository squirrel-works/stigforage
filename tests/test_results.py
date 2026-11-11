"""`import-results` unit 1: XCCDF results and ARF (ADR 0003).

The result files under fixtures/xccdf-results are real SCC, Evaluate-STIG and STIG Manager
output from the public STIG Manager test files (MIT; see NOTICE), plus a real OpenSCAP ARF
generated for this project against DISA's RHEL 9 V2R10 SCAP benchmark and its matching manual
checklist, both truncated to 10 rules (see NOTICE).
"""

from __future__ import annotations

import copy
import io
from pathlib import Path
from typing import Any

import pytest

from conftest import FIXTURES
from stigforage import cklb, xccdf
from stigforage.cli import EXIT_OK, EXIT_UNREADABLE, run
from stigforage.model import Checklist, ChecklistError, Rule, Status, Stig
from stigforage.results import (
    RuleResult,
    Scan,
    import_results,
    load_xccdf_results,
    loads_xccdf_results,
    release_id,
)

RES = FIXTURES / "xccdf-results"
SCC = RES / "scc_scan-xccdf.xml"
EVAL_STIG = RES / "eval-stig-w-sm-resultEngine.xml"
VPN_A_RESULTS = RES / "Asset_a-VPN_TRUNCATED-V2R5-xccdf.xml"
VPN_B_RESULTS = RES / "Asset_b-VPN_TRUNCATED-V2R5-xccdf.xml"
ALL_RESULTS = RES / "all-possible-results-xccdf.xml"
VPN_XCCDF = FIXTURES / "xccdf" / "U_VPN_SRG_V2R5_Manual-xccdf-truncated.xml"
VPN_A = FIXTURES / "cklb" / "Asset_a-VPN_TRUNCATED-V2R5.cklb"
CHROME_V2R8 = FIXTURES / "cklb" / "CA1294WK16078_Chrome_V2R8_20231211-125633Trimmed.cklb"
OPENSCAP_ARF = RES / "openscap-RHEL_9-V2R10-arf-truncated.xml"
RHEL9_MANUAL = RES / "RHEL_9-V2R10-manual-truncated.cklb"
SCHEMA = FIXTURES / "schema" / "SV3_CKLB_1_0_JSON_SCHEMA.json"
XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"


def _rule(group: str = "V-1", src: str = "SV-1r1_rule", **kw: Any) -> Rule:
    base: dict[str, Any] = {
        "group_id": group,
        "rule_id": src.removesuffix("_rule"),
        "rule_version": "X-1",
        "severity": "medium",
        "status": Status.NOT_REVIEWED,
        "rule_id_src": src,
    }
    return Rule(**{**base, **kw})


def _checklist(*rules: Rule, host: str = "", release: str = "Release: 1") -> Checklist:
    stig = Stig("n", "n", "S", release, list(rules), version=1)
    return Checklist("t", "i", {"host_name": host}, [stig])


def _scan(*results: RuleResult, **kw: Any) -> Scan:
    base: dict[str, Any] = {
        "source": "scan.xml",
        "tool": "cpe:/a:test:scanner:1.0",
        "end_time": "2026-11-10T12:00:00",
        "stig_id": "S",
        "version": "V1R1",
        "release_info": "",
        "hosts": (),
    }
    return Scan(**{**base, **kw}, results=list(results))


def _result(
    value: str = "pass", src: str = "SV-1r1_rule", group: str = "V-1", details: str = ""
) -> RuleResult:
    return RuleResult(src, group, value, details)


def _cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return run(list(argv), out=out), out.getvalue()


# --- release identity -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("version", "release_info", "expected"),
    [
        ("V2R5", "", (2, 5)),  # STIG Manager, Evaluate-STIG
        ("002.010", "Benchmark Date: 30 Sep 2026", (2, 10)),  # DISA SCAP benchmark
        ("6.3.3", "Enhanced Content 6.3.3, based on Release: 6.3", (6, 3)),  # SCC enhanced
        ("2", "Release: 10 Benchmark Date: 30 Sep 2026", (2, 10)),  # manual STIG
        (2, "Release: 10 Benchmark Date: 30 Sep 2026", (2, 10)),
        (None, "Release: 8 Benchmark Date: 26 Jan 2023", (None, 8)),  # schema-valid CKLB
        ("", "", None),
        ("draft", "no release here", None),
    ],
)
def test_release_id_reads_every_form_seen_in_real_files(
    version: object, release_info: str, expected: tuple[int | None, int] | None
) -> None:
    assert release_id(version, release_info) == expected


# --- parsing --------------------------------------------------------------------------------


def test_scc_scan_is_parsed_with_v_numbers_messages_and_host() -> None:
    [scan] = load_xccdf_results(SCC)
    assert scan.stig_id == "MOZ_Firefox_Linux"
    assert release_id(scan.version, scan.release_info) == (6, 3)
    assert scan.tool == "cpe:/a:niwc:scc:5.8"
    assert "WORK-UBUNTU" in scan.hosts
    assert len(scan.results) == 34
    assert all(r.group_id.startswith("V-") and r.details for r in scan.results)
    assert scan.results[0].rule_id_src == "SV-251545r879827_rule"  # prefix dropped


def test_evaluate_stig_results_have_rule_ids_but_no_v_numbers() -> None:
    [scan] = load_xccdf_results(EVAL_STIG)
    assert scan.stig_id == "Google_Chrome_Current_Windows"
    assert release_id(scan.version, scan.release_info) == (2, 9)
    assert {r.group_id for r in scan.results} == {""}
    assert {"host-123456", "host-123456.mil"} <= set(scan.hosts)


def test_every_xccdf_result_value_is_kept_as_written() -> None:
    [scan] = load_xccdf_results(ALL_RESULTS)
    assert sorted(r.result for r in scan.results) == sorted(
        ["pass", "fail", "notapplicable", "notchecked", "unknown", "error", "notselected", "fixed"]
    )


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("NoTestResult-xccdf.xml", "no TestResult element"),
        ("NoBenchMarkElement.xml", "neither an XCCDF Benchmark nor an ARF"),
        ("NoRuleResultElement-xccdf..xml", "holds no rule-result elements"),
    ],
)
def test_malformed_result_files_are_refused(name: str, message: str) -> None:
    with pytest.raises(ChecklistError, match=message):
        load_xccdf_results(RES / name)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("<rule-result><result>pass</result></rule-result>", "missing idref"),
        ('<rule-result idref="SV-1r1_rule"/>', "missing result"),
    ],
)
def test_rule_results_missing_required_fields_are_refused(body: str, message: str) -> None:
    doc = f'<Benchmark xmlns="{XCCDF_NS}" id="b"><TestResult id="t">{body}</TestResult></Benchmark>'
    with pytest.raises(ChecklistError, match=message):
        loads_xccdf_results(doc.encode())


def _split_vpn_results() -> tuple[str, str]:
    """The VPN results fixture as (Benchmark without its TestResult, TestResult)."""
    text = VPN_A_RESULTS.read_text("utf-8").split("?>", 1)[1]
    start, end = text.index("<TestResult"), text.index("</TestResult>") + len("</TestResult>")
    test_result = text[start:end].replace(
        "<TestResult ", f'<TestResult xmlns="{XCCDF_NS}" xmlns:sm="sm" ', 1
    )
    return text[:start] + text[end:], test_result


ARF = "http://scap.nist.gov/schema/asset-reporting-format/1.1"


def test_arf_with_the_benchmark_inside_the_report() -> None:
    text = VPN_A_RESULTS.read_text("utf-8").split("?>", 1)[1]
    doc = (
        f'<arf:asset-report-collection xmlns:arf="{ARF}"><arf:reports><arf:report id="r1">'
        f"<arf:content>{text}</arf:content></arf:report></arf:reports></arf:asset-report-collection>"
    )
    [scan] = loads_xccdf_results(doc.encode())
    assert [r.result for r in scan.results] == [
        r.result for r in load_xccdf_results(VPN_A_RESULTS)[0].results
    ]


def test_arf_with_the_benchmark_in_report_requests_like_openscap() -> None:
    benchmark, test_result = _split_vpn_results()
    doc = (
        f'<arf:asset-report-collection xmlns:arf="{ARF}">'
        f'<arf:report-requests><arf:report-request id="q1"><arf:content>{benchmark}'
        "</arf:content></arf:report-request></arf:report-requests>"
        f'<arf:reports><arf:report id="r1"><arf:content>{test_result}</arf:content></arf:report>'
        "</arf:reports></arf:asset-report-collection>"
    )
    [scan] = loads_xccdf_results(doc.encode())
    assert scan.stig_id == "VPN_TRUNCATED"
    assert release_id(scan.version, scan.release_info) == (2, 5)
    assert all(r.group_id for r in scan.results)  # V-numbers found in the separate Benchmark


# --- applying -------------------------------------------------------------------------------


def test_results_map_to_statuses_and_the_rest_are_counted() -> None:
    rules = [_rule(f"V-{i}", f"SV-{i}r1_rule") for i in range(9)]
    values = ["pass", "fail", "notapplicable", "notchecked", "error", "unknown", "notselected",
              "informational", "fixed"]  # fmt: skip
    scan = _scan(*(_result(v, f"SV-{i}r1_rule", f"V-{i}") for i, v in enumerate(values)))
    result = import_results(_checklist(*rules), [scan])
    statuses = [r.status for r in result.checklist.stigs[0].rules]
    assert statuses[:3] == [Status.NOT_A_FINDING, Status.OPEN, Status.NOT_APPLICABLE]
    assert set(statuses[3:]) == {Status.NOT_REVIEWED}
    [report] = result.scans
    assert report.applied == 3
    assert dict(report.not_imported) == dict.fromkeys(values[3:], 1)


def test_finding_details_get_a_source_line_and_comments_overrides_are_untouched() -> None:
    rule = _rule(comments="assessor notes", overrides={"severity": {"x": "y"}})
    scan = _scan(_result("fail", details="setting X is 0"))
    out = import_results(_checklist(rule), [scan]).checklist.stigs[0].rules[0]
    assert out.finding_details == (
        "[stigforage import-results] cpe:/a:test:scanner:1.0, scan ended 2026-11-10T12:00:00: "
        "fail\nsetting X is 0"
    )
    assert (out.comments, out.overrides) == ("assessor notes", {"severity": {"x": "y"}})


def test_checklist_wins_conflicts_unless_prefer_results() -> None:
    checklist = _checklist(
        _rule("V-1", "SV-1r1_rule", status=Status.NOT_A_FINDING),  # differs: conflict
        _rule("V-2", "SV-2r1_rule", status=Status.OPEN),  # same: unchanged
        _rule("V-3", "SV-3r1_rule", finding_details="manual notes"),  # would be replaced
    )
    scan = _scan(
        _result("fail", "SV-1r1_rule", "V-1"),
        _result("fail", "SV-2r1_rule", "V-2"),
        _result("pass", "SV-3r1_rule", "V-3"),
    )
    kept = import_results(checklist, [scan])
    [report] = kept.scans
    assert (report.applied, report.unchanged) == (0, 1)
    assert [(c.group_id, c.reason) for c in report.conflicts] == [
        ("V-1", "status"),
        ("V-3", "finding_details"),
    ]
    assert [r.status for r in kept.checklist.stigs[0].rules] == [
        Status.NOT_A_FINDING,
        Status.OPEN,
        Status.NOT_REVIEWED,
    ]
    won = import_results(checklist, [scan], prefer="results").checklist.stigs[0].rules
    assert [r.status for r in won] == [Status.OPEN, Status.OPEN, Status.NOT_A_FINDING]
    assert won[2].finding_details is not None and "manual notes" not in won[2].finding_details


def test_a_different_rule_revision_matches_by_v_number() -> None:
    # 156 of 393 rules differ in revision between DISA's SCAP and manual RHEL 9 V2R10.
    checklist = _checklist(_rule("V-1", "SV-1r2_rule"))
    [report] = import_results(checklist, [_scan(_result("fail", "SV-1r1_rule", "V-1"))]).scans
    assert (report.applied, report.matched_by_group_id) == (1, 1)


def test_without_v_numbers_only_exact_rule_ids_match() -> None:
    checklist = _checklist(_rule("V-1", "SV-1r2_rule"))
    [report] = import_results(checklist, [_scan(_result("fail", "SV-1r1_rule", ""))]).scans
    assert report.applied == 0
    assert [r.rule_id_src for r in report.unmatched] == ["SV-1r1_rule"]


def test_inputs_are_never_mutated() -> None:
    checklist = _checklist(_rule())
    scan = _scan(_result("fail"))
    before = (copy.deepcopy(checklist), copy.deepcopy(scan))
    import_results(checklist, [scan], prefer="results")
    assert (checklist, scan) == before


# --- refusals and warnings ------------------------------------------------------------------


def test_scan_for_a_stig_not_in_the_checklist_is_refused() -> None:
    with pytest.raises(ChecklistError, match="no STIG with that id"):
        import_results(_checklist(_rule()), [_scan(_result(), stig_id="OTHER")])


def test_two_scans_for_the_same_stig_are_refused() -> None:
    with pytest.raises(ChecklistError, match="another results file is also for"):
        import_results(_checklist(_rule()), [_scan(_result()), _scan(_result())])


def test_real_scan_of_another_release_is_refused() -> None:
    # Evaluate-STIG scanned Chrome V2R9; the checklist is Chrome Release 8 with no version.
    with pytest.raises(ChecklistError, match=r"V2R9 but the checklist STIG is V\?R8"):
        import_results(cklb.load(CHROME_V2R8), load_xccdf_results(EVAL_STIG))


def test_same_release_number_of_another_version_is_refused() -> None:
    # The checklist is version 1, Release 1; the scan is V2R1.
    with pytest.raises(ChecklistError, match="V2R1 but the checklist STIG is V1R1"):
        import_results(_checklist(_rule()), [_scan(_result(), version="V2R1")])


def test_unknown_release_is_a_warning_not_a_refusal() -> None:
    result = import_results(_checklist(_rule(), release=""), [_scan(_result(), version="")])
    assert any("release could not be compared" in w for w in result.warnings)


@pytest.mark.parametrize(
    ("checklist_host", "scan_hosts", "refused"),
    [
        ("web01", ("db01",), True),
        ("web01", ("WEB01.example.mil",), False),  # short name, any case
        ("web01.example.mil", ("other", "web01"), False),  # host_name fact
        ("", ("db01",), False),  # blank checklist (e.g. from a benchmark)
    ],
)
def test_host_must_match_unless_allowed(
    checklist_host: str, scan_hosts: tuple[str, ...], refused: bool
) -> None:
    checklist, scan = _checklist(_rule(), host=checklist_host), _scan(_result(), hosts=scan_hosts)
    if refused:
        with pytest.raises(ChecklistError, match="--allow-host-mismatch"):
            import_results(checklist, [scan])
        allowed = import_results(checklist, [scan], allow_host_mismatch=True)
        assert any("imported anyway" in w for w in allowed.warnings)
        assert allowed.scans[0].applied == 1
    else:
        assert import_results(checklist, [scan]).scans[0].applied == 1


def test_scan_without_a_host_is_a_warning() -> None:
    result = import_results(_checklist(_rule(), host="web01"), [_scan(_result())])
    assert any("names no host" in w for w in result.warnings)


# --- real files end to end ------------------------------------------------------------------


def test_stig_manager_results_reproduce_the_checklist_they_came_from() -> None:
    blank = xccdf.load(VPN_XCCDF).checklist
    result = import_results(blank, load_xccdf_results(VPN_A_RESULTS))
    [report] = result.scans
    assert report.applied == 6
    assert dict(report.not_imported) == {"notchecked": 3, "informational": 1}
    source = {r.group_id: r.status for r in cklb.load(VPN_A).stigs[0].rules}
    for rule in result.checklist.stigs[0].rules:
        if rule.status != Status.NOT_REVIEWED:
            assert rule.status == source[rule.group_id]


def test_scc_scan_applies_to_a_checklist_made_from_its_own_scap_benchmark() -> None:
    # The checklist's STIG id keeps the SCAP prefix; pairing drops it on both sides.
    checklist = xccdf.loads(SCC.read_bytes(), source="scc").checklist
    assert checklist.stigs[0].stig_id.startswith("xccdf_mil.disa.stig_benchmark_")
    [report] = import_results(checklist, load_xccdf_results(SCC)).scans
    assert (report.applied, dict(report.not_imported)) == (32, {"notchecked": 2})


def test_real_openscap_arf_is_read_from_its_separate_report_sections() -> None:
    # OpenSCAP keeps the TestResult in reports and the Benchmark in report-requests.
    [scan] = load_xccdf_results(OPENSCAP_ARF)
    assert scan.stig_id == "RHEL_9_STIG"
    assert release_id(scan.version, scan.release_info) == (2, 10)  # from "002.010"
    assert scan.tool == "cpe:/a:redhat:openscap:1.3.14"
    assert set(scan.hosts) == {"scanned-container"}
    assert sorted(r.result for r in scan.results) == sorted(
        ["pass"] * 3 + ["fail"] * 3 + ["notapplicable"] * 2 + ["error"] * 2
    )
    assert all(r.group_id.startswith("V-") for r in scan.results)


def test_real_openscap_arf_imports_into_the_manual_checklist_of_the_same_release() -> None:
    # SCAP and manual rule revisions differ for 7 of these 10 rules, as they do for 156 of the
    # full benchmark's 393, so those match by V-number only.
    result = import_results(cklb.load(RHEL9_MANUAL), load_xccdf_results(OPENSCAP_ARF))
    [report] = result.scans
    assert (report.applied, report.matched_by_group_id) == (8, 7)
    assert (dict(report.not_imported), report.unmatched, report.conflicts) == ({"error": 2}, [], [])
    assert result.warnings == []


# --- CLI ------------------------------------------------------------------------------------


def test_cli_import_results_is_a_dry_run_by_default(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _cli("import-results", str(VPN_XCCDF), str(VPN_A_RESULTS), "-o", str(dest))
    assert code == EXIT_OK
    assert "applied=6 unchanged=0 conflicts=0 unmatched=0" in out
    assert "not_imported: informational=1, notchecked=3" in out
    assert "dry run: would write" in out
    assert not dest.exists()


def test_cli_import_results_apply_writes_a_schema_valid_checklist(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    code, _ = _cli("import-results", str(VPN_XCCDF), str(VPN_A_RESULTS), "-o", str(dest), "--apply")
    assert code == EXIT_OK
    statuses = [r.status for r in cklb.load(dest).stigs[0].rules]
    assert statuses.count(Status.NOT_REVIEWED) == 4
    assert _cli("validate", "--schema", str(SCHEMA), str(dest))[0] == EXIT_OK


def test_cli_host_mismatch_and_prefer_results(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Asset_b's scan against Asset_a's checklist: a different host, and conflicting reviews.
    dest = tmp_path / "out.cklb"
    code, out = _cli("import-results", str(VPN_A), str(VPN_B_RESULTS), "-o", str(dest))
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert "--allow-host-mismatch" in capsys.readouterr().err
    code, out = _cli(
        "import-results", str(VPN_A), str(VPN_B_RESULTS), "-o", str(dest), "--allow-host-mismatch"
    )
    assert code == EXIT_OK
    assert "  ! V-" in out and "kept checklist" in out
    assert "imported anyway" in capsys.readouterr().err
    _, preferred = _cli(
        "import-results",
        str(VPN_A),
        str(VPN_B_RESULTS),
        "-o",
        str(dest),
        "--allow-host-mismatch",
        "--prefer",
        "results",
    )
    assert "kept results" in preferred


@pytest.mark.parametrize(
    ("checklist", "results", "message"),
    [
        (CHROME_V2R8, EVAL_STIG, "results only apply to the release they scanned"),
        (VPN_XCCDF, RES / "NoTestResult-xccdf.xml", "cannot read results"),
        (VPN_XCCDF, SCC, "no STIG with that id"),
    ],
)
def test_cli_refusals_exit_2_and_write_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], checklist: Path, results: Path, message: str
) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _cli("import-results", str(checklist), str(results), "-o", str(dest), "--apply")
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert message in capsys.readouterr().err
    assert not dest.exists()


def test_cli_two_results_files_for_one_stig_are_refused(tmp_path: Path) -> None:
    code, _ = _cli(
        "import-results",
        str(VPN_XCCDF),
        str(VPN_A_RESULTS),
        str(VPN_B_RESULTS),
        "-o",
        str(tmp_path / "o.cklb"),
    )
    assert code == EXIT_UNREADABLE


def test_cli_output_may_not_be_an_input(tmp_path: Path) -> None:
    checklist = tmp_path / "c.cklb"
    checklist.write_bytes(VPN_A.read_bytes())
    code, _ = _cli(
        "import-results", str(checklist), str(VPN_A_RESULTS), "-o", str(checklist), "--force"
    )
    assert code == EXIT_UNREADABLE
    assert checklist.read_bytes() == VPN_A.read_bytes()
