"""`import-results` unit 3: SARIF findings attached to a named rule (ADR 0003 decision 8).

Fixtures under fixtures/sarif are unmodified real output: Flawfinder (via MITRE Heimdall), and
the Trivy and Grype projects' own SARIF test files (Apache-2.0; see NOTICE).
"""

from __future__ import annotations

import io
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from conftest import FIXTURES
from stigforage import cklb, xccdf
from stigforage.cli import EXIT_OK, EXIT_UNREADABLE, run
from stigforage.findings import (
    MAX_LISTED,
    Finding,
    FindingsFile,
    load_sarif,
    loads_sarif,
    scan_for_rule,
)
from stigforage.model import ChecklistError, Status
from stigforage.results import import_results

SARIF = FIXTURES / "sarif"
FLAWFINDER = SARIF / "heimdall2-flawfinder.sarif"
TRIVY = SARIF / "trivy-alpine-310.sarif"
GRYPE = SARIF / "grype-image.sarif"
VPN_XCCDF = FIXTURES / "xccdf" / "U_VPN_SRG_V2R5_Manual-xccdf-truncated.xml"
VPN_A_RESULTS = FIXTURES / "xccdf-results" / "Asset_a-VPN_TRUNCATED-V2R5-xccdf.xml"
SCHEMA = FIXTURES / "schema" / "SV3_CKLB_1_0_JSON_SCHEMA.json"
RULE = "V-207184"  # any rule of the VPN fixture; the user chooses which rule a scan evidences


def _sarif(*results: dict[str, Any], rules: list[dict[str, Any]] | None = None) -> str:
    driver = {"name": "tool", "version": "1.0", "rules": rules or []}
    return json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": list(results)}]})  # fmt: skip


def _result(**kw: Any) -> dict[str, Any]:
    return {"ruleId": "R1", "level": "error", "message": {"text": "bad"}, **kw}


def _blank_vpn() -> Any:
    return xccdf.load(VPN_XCCDF).checklist


def _cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return run(list(argv), out=out), out.getvalue()


# --- reading real SARIF ---------------------------------------------------------------------


def test_real_flawfinder_sarif() -> None:
    [file] = load_sarif(FLAWFINDER)
    assert file.tool == "Flawfinder 2.0.15"
    # 7 results have no level; their rules' defaults (or SARIF's "warning") apply.
    assert Counter(f.level for f in file.findings) == {"error": 35, "warning": 7, "note": 35}
    assert file.findings[0].location == "test/test-patched.c:36"


def test_real_trivy_sarif_messages_become_one_line() -> None:
    [file] = load_sarif(TRIVY)
    assert (file.tool, len(file.findings)) == ("Trivy dev", 4)
    assert {f.rule_id for f in file.findings} == {"CVE-2019-1549", "CVE-2019-1551"}
    assert all("\n" not in f.message for f in file.findings)


def test_real_grype_sarif() -> None:
    [file] = load_sarif(GRYPE)
    assert file.tool == "grype 0.0.0-dev"
    assert sorted(f.level for f in file.findings) == ["error", "note"]


# --- what counts as a finding ---------------------------------------------------------------


def test_level_falls_back_to_the_rule_default_then_warning() -> None:
    rules: list[dict[str, Any]] = [
        {"id": "R1", "defaultConfiguration": {"level": "note"}},
        {"id": "R2"},
    ]
    [file] = loads_sarif(_sarif(_result(level=None), _result(ruleId="R2", level=None), rules=rules))
    assert [f.level for f in file.findings] == ["note", "warning"]


def test_rule_index_names_the_rule_when_rule_id_is_absent() -> None:
    [file] = loads_sarif(_sarif(_result(ruleId=None, ruleIndex=0), rules=[{"id": "CVE-1"}]))
    assert file.findings[0].rule_id == "CVE-1"


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        ({"kind": "pass"}, "kind pass"),
        ({"kind": "notApplicable"}, "kind notApplicable"),
        ({"kind": "informational"}, "kind informational"),
        ({"kind": "review"}, "kind review"),  # needs a person, not a confirmed failure
        ({"suppressions": [{"status": "accepted"}]}, "suppressed"),
        ({"suppressions": [{"kind": "inSource"}]}, "suppressed"),  # no status means accepted
        ({"baselineState": "absent"}, "absent from this run"),
    ],
)
def test_results_that_are_not_findings_are_tallied(extra: dict[str, Any], reason: str) -> None:
    [file] = loads_sarif(_sarif(_result(**extra)))
    assert (file.findings, dict(file.not_counted)) == ([], {reason: 1})


@pytest.mark.parametrize(
    "extra",
    [
        {"suppressions": [{"status": "underReview"}]},  # proposed, not accepted
        {"suppressions": [{"status": "rejected"}]},
        {"baselineState": "new"},
        {"kind": "fail", "level": "note"},  # every level counts
    ],
)
def test_results_that_still_count(extra: dict[str, Any]) -> None:
    [file] = loads_sarif(_sarif(_result(**extra)))
    assert len(file.findings) == 1


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        ("{", "invalid JSON"),
        ('{"version": "2.1.0", "runs": NaN}', "invalid JSON constant"),
        ('{"version": "2.0.0", "runs": []}', "expected SARIF 2.1.0"),
        ('{"version": "2.1.0", "runs": []}', "no runs"),
        ('{"version": "2.1.0", "runs": [{"tool": {"driver": {}}}]}', "missing name"),
        (_sarif(_result(level="critical")), "unknown level 'critical'"),
    ],
)
def test_malformed_sarif_is_refused(doc: str, message: str) -> None:
    with pytest.raises(ChecklistError, match=message):
        loads_sarif(doc)


# --- the summary ----------------------------------------------------------------------------


def test_rule_must_be_a_v_number() -> None:
    with pytest.raises(ChecklistError, match="not a V-number"):
        scan_for_rule("CVE-2019-1549", load_sarif(TRIVY))


def test_summary_lists_findings_up_to_the_cap_and_keeps_counts_complete() -> None:
    many = FindingsFile(
        "big.sarif", "scanner 1", [Finding(f"CVE-{i}", "warning", "m", "") for i in range(60)]
    )
    many.not_counted["suppressed"] = 2
    [result] = scan_for_rule(RULE, [many]).results
    lines = result.details.splitlines()
    assert (
        lines[0] == "scanner 1 (big.sarif): 60 finding(s) (warning 60); not counted: suppressed 2"
    )
    assert len(lines) == 1 + MAX_LISTED + 1
    assert lines[-1] == f"  ... and {60 - MAX_LISTED} more"


def test_no_findings_is_not_imported() -> None:
    clean = FindingsFile("clean.sarif", "scanner 1", [])
    [result] = scan_for_rule(RULE, [clean]).results
    assert result.result == "no_findings"


# --- applying -------------------------------------------------------------------------------


def test_findings_open_the_named_rule_and_leave_comments_alone() -> None:
    checklist = _blank_vpn()
    target = next(r for r in checklist.stigs[0].rules if r.group_id == RULE)
    target.comments = "assessor notes"
    result = import_results(checklist, [scan_for_rule(RULE, load_sarif(TRIVY) + load_sarif(GRYPE))])
    rule = next(r for r in result.checklist.stigs[0].rules if r.group_id == RULE)
    assert rule.status == Status.OPEN
    assert rule.comments == "assessor notes"
    assert rule.finding_details is not None
    assert "Trivy dev (" in rule.finding_details and "grype 0.0.0-dev (" in rule.finding_details
    assert "CVE-2019-1551 [warning]" in rule.finding_details
    others = [r.status for r in result.checklist.stigs[0].rules if r.group_id != RULE]
    assert set(others) == {Status.NOT_REVIEWED}


def test_a_clean_scan_leaves_the_status_alone() -> None:
    checklist = _blank_vpn()
    clean = FindingsFile("clean.sarif", "scanner 1", [])
    result = import_results(checklist, [scan_for_rule(RULE, [clean])])
    assert dict(result.scans[0].not_imported) == {"no_findings": 1}
    assert result.checklist == checklist


def test_findings_conflict_with_a_reviewed_rule_unless_prefer_results() -> None:
    checklist = _blank_vpn()
    next(r for r in checklist.stigs[0].rules if r.group_id == RULE).status = Status.NOT_A_FINDING
    scan = scan_for_rule(RULE, load_sarif(TRIVY))
    kept = import_results(checklist, [scan])
    assert [c.group_id for c in kept.scans[0].conflicts] == [RULE]
    won = import_results(checklist, [scan], prefer="results")
    assert next(r for r in won.checklist.stigs[0].rules if r.group_id == RULE).status == Status.OPEN


def test_a_rule_not_in_the_checklist_is_refused() -> None:
    with pytest.raises(ChecklistError, match="none of the scan's 1 V-numbers"):
        import_results(_blank_vpn(), [scan_for_rule("V-999999", load_sarif(TRIVY))])


def test_sarif_matches_by_v_number_without_a_drift_warning() -> None:
    # SARIF names no rule id, so it always matches by V-number; that is not revision drift.
    result = import_results(_blank_vpn(), [scan_for_rule(RULE, load_sarif(TRIVY))])
    assert result.scans[0].matched_by_group_id == 1
    assert not any("different rule revision" in w for w in result.warnings)
    assert any("release could not be compared" in w for w in result.warnings)


# --- CLI ------------------------------------------------------------------------------------


def test_cli_sarif_opens_the_rule_in_a_schema_valid_checklist(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _cli("import-results", str(VPN_XCCDF), str(TRIVY), str(GRYPE),
                     "--rule", RULE, "-o", str(dest), "--apply")  # fmt: skip
    assert code == EXIT_OK
    assert "applied=1" in out
    rule = next(r for r in cklb.load(dest).stigs[0].rules if r.group_id == RULE)
    assert rule.status == Status.OPEN
    assert _cli("validate", "--schema", str(SCHEMA), str(dest))[0] == EXIT_OK


@pytest.mark.parametrize(
    ("files", "rule", "message"),
    [
        ((TRIVY,), None, "SARIF results need --rule"),
        ((VPN_A_RESULTS,), RULE, "--rule only applies to SARIF results"),
    ],
)
def test_cli_sarif_and_rule_go_together(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    files: tuple[Path, ...],
    rule: str | None,
    message: str,
) -> None:
    argv = ["import-results", str(VPN_XCCDF), *map(str, files), "-o", str(tmp_path / "o.cklb")]
    code, out = _cli(*argv, *(["--rule", rule] if rule else []))
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert message in capsys.readouterr().err


def test_cli_rejects_a_rule_that_is_not_a_v_number(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        _cli("import-results", str(VPN_XCCDF), str(TRIVY), "--rule", "CVE-2019-1549",
             "-o", str(tmp_path / "o.cklb"))  # fmt: skip
    assert exc.value.code == 2


def test_cli_sarif_and_a_scan_of_the_same_stig_are_one_scan_too_many(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Both pair with VPN_TRUNCATED: one scan per STIG per run (decision 1).
    code, _ = _cli("import-results", str(VPN_XCCDF), str(VPN_A_RESULTS), str(TRIVY),
                   "--rule", RULE, "-o", str(tmp_path / "o.cklb"))  # fmt: skip
    assert code == EXIT_UNREADABLE
    assert "another results file is also for 'VPN_TRUNCATED'" in capsys.readouterr().err
