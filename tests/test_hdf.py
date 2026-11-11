"""`import-results` unit 2: InSpec / Heimdall HDF (ADR 0003 decision 3 and unit 2 notes).

The files under fixtures/hdf come from github.com/mitre/heimdall2 (Apache-2.0; see NOTICE). Two
are cut down to a dozen controls and say so in a `_stigforage_note` key.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import FIXTURES
from stigforage import cklb, xccdf
from stigforage.cli import EXIT_OK, EXIT_UNREADABLE, run
from stigforage.hdf import load_hdf, loads_hdf
from stigforage.model import (
    Checklist,
    ChecklistError,
    Rule,
    Status,
    Stig,
    default_target_data,
    make_checklist,
    make_rule,
    make_stig,
    new_uuid,
)
from stigforage.results import import_results, release_id

HDF = FIXTURES / "hdf"
RHEL7 = HDF / "rhel7-results-truncated.json"  # disa_stig-el7, title "... v1r4"
OVERLAY = HDF / "example-3-layer-overlay-truncated.json"  # three profiles, results in the base
RHEL9_V1R3 = HDF / "small_overrides_hdf.json"  # STIGRef "Version 1, Release: 3"
RHEL9_V1R1 = FIXTURES / "xccdf" / "U_RHEL_9_STIG_V1R1_Manual-xccdf-truncated.xml"
VPN_A = FIXTURES / "cklb" / "Asset_a-VPN_TRUNCATED-V2R5.cklb"
SCHEMA = FIXTURES / "schema" / "SV3_CKLB_1_0_JSON_SCHEMA.json"


def _control(cid: str = "V-1", impact: float = 0.5, *statuses: str, **tags: Any) -> dict[str, Any]:
    return {
        "id": cid,
        "impact": impact,
        "tags": {"gid": cid, "rid": f"S{cid}r1_rule", **tags},
        "results": [
            {"status": s, "code_desc": f"test {i}", "start_time": f"2026-11-10T0{i}:00:00"}
            for i, s in enumerate(statuses)
        ],
    }


def _hdf(*controls: dict[str, Any], **profile: Any) -> str:
    base = {"name": "p", "version": "1.0.0", "title": "t", "controls": list(controls)}
    return json.dumps({"version": "5.0", "platform": {"name": "rhel", "release": "9"},
                       "profiles": [{**base, **profile}]})  # fmt: skip


def _checklist_for(*v_numbers: str, release: str = "Release: 4", version: int = 1) -> Checklist:
    rules = [
        Rule(v, f"S{v}r1", "X", "medium", Status.NOT_REVIEWED, rule_id_src=f"S{v}r1_rule")
        for v in v_numbers
    ]
    return Checklist("t", "i", {}, [Stig("n", "n", "S", release, rules, version=version)])


def _cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return run(list(argv), out=out), out.getvalue()


# --- control status ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("impact", "statuses", "expected"),
    [
        # Heimdall's order (inspecjs compute_status): error, impact 0, no results, failed,
        # passed, skipped.
        (0.5, ("failed",), "fail"),
        (0.5, ("passed", "failed"), "fail"),
        (0.5, ("failed", "skipped", "error"), "error"),  # Heimdall: Profile Error
        (0.5, ("passed", "passed"), "pass"),
        (0.5, ("passed", "skipped"), "pass"),  # Heimdall: Passed
        (0.0, ("failed",), "notapplicable"),  # impact 0 is InSpec's not-applicable marker
        (0.0, ("skipped",), "notapplicable"),
        (0.0, ("error",), "error"),  # error outranks impact 0
        (0.0, (), "notapplicable"),
        (0.5, ("skipped",), "skipped"),
        (0.5, ("passed", "error"), "error"),
        (0.5, (), "no_results"),
    ],
)
def test_control_result_follows_heimdall(
    impact: float, statuses: tuple[str, ...], expected: str
) -> None:
    [scan] = loads_hdf(_hdf(_control("V-1", impact, *statuses), _control("V-2", 0.5, "passed")))
    assert scan.results[0].result == expected


def test_a_result_with_a_backtrace_is_an_error() -> None:
    control = _control("V-1", 0.5, "passed")
    control["results"][0]["backtrace"] = ["profile/controls/V-1.rb:12"]
    [scan] = loads_hdf(_hdf(control))
    assert scan.results[0].result == "error"


@pytest.mark.parametrize(
    ("impact", "statuses", "expected"),
    [
        (0.5, ("skipped",), "waived"),  # Heimdall: Not Applicable; here, not imported
        (0.0, ("skipped",), "waived"),
        (0.5, ("failed",), "waived"),
        (0.5, ("error",), "error"),  # error still outranks a waiver, as in Heimdall
    ],
)
def test_waived_controls_are_not_imported(
    impact: float, statuses: tuple[str, ...], expected: str
) -> None:
    control = _control("V-1", impact, *statuses)
    control["waiver_data"] = {"skipped_due_to_waiver": True, "justification": "accepted"}
    [scan] = loads_hdf(_hdf(control))
    assert scan.results[0].result == expected
    result = import_results(_checklist_for("V-1"), [scan])
    assert result.checklist.stigs[0].rules[0].status == Status.NOT_REVIEWED
    assert dict(result.scans[0].not_imported) == {expected: 1}


def test_details_list_each_test_and_scan_time_is_the_latest_result() -> None:
    control = _control("V-1", 0.5, "passed", "failed")
    control["results"][1]["message"] = "expected 0, got 1"
    [scan] = loads_hdf(_hdf(control))
    assert scan.results[0].details == "[passed] test 0\n[failed] test 1: expected 0, got 1"
    assert scan.end_time == "2026-11-10T01:00:00"
    assert (scan.stig_id, scan.hosts) == ("", ())


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        ("{", "invalid JSON"),
        ('{"profiles": NaN}', "invalid JSON constant"),
        ('{"profiles": {}}', "expected array"),
        (
            '{"profiles": [{"name": "p", "controls": [{"id": "V-1"}]}]}',
            "no profile holds any results",
        ),
        (
            '{"profiles": [{"controls": [{"results": [{"status": "passed"}]}]}]}',
            "control has no id",
        ),
        (
            '{"profiles": [{"controls": [{"id": "V-1", "results": [{"status": "odd"}]}]}]}',
            "unknown status 'odd'",
        ),
    ],
)
def test_malformed_hdf_is_refused(doc: str, message: str) -> None:
    with pytest.raises(ChecklistError, match=message):
        loads_hdf(doc)


def test_parent_profile_loop_is_refused_not_followed_forever() -> None:
    a = {"name": "a", "parent_profile": "b", "controls": [_control("V-1", 0.5, "passed")]}
    b = {"name": "b", "parent_profile": "a", "controls": [{"id": "V-1", "impact": 0.5}]}
    with pytest.raises(ChecklistError, match="parent_profile links form a loop"):
        loads_hdf(json.dumps({"profiles": [a, b]}))


# --- release identity -------------------------------------------------------------------------


def test_release_comes_from_stigref_then_title_else_unknown() -> None:
    ref = "RHEL 9 STIG :: Version 1, Release: 3 Benchmark Date: 24 Apr 2024"
    [by_ref] = loads_hdf(_hdf(_control("V-1", 0.5, "passed", STIGRef=ref)))
    [by_title] = loads_hdf(_hdf(_control("V-1", 0.5, "passed"), title="DISA RHEL 7 STIG - v1r4"))
    [unknown] = loads_hdf(_hdf(_control("V-1", 0.5, "passed"), version="2.6.0"))
    assert release_id(by_ref.version, by_ref.release_info) == (1, 3)
    assert release_id(by_title.version, by_title.release_info) == (1, 4)
    # The profile's own version is not a STIG release: real files pair 0.2.0 with "v1r4".
    assert release_id(unknown.version, unknown.release_info) is None


# --- real files -------------------------------------------------------------------------------


def test_real_inspec_run_maps_every_result_mix() -> None:
    [scan] = load_hdf(RHEL7)
    assert release_id(scan.version, scan.release_info) == (1, 4)
    assert scan.tool == "disa_stig-el7 0.2.0 (HDF, centos 7.6.1810)"
    counts: dict[str, int] = {}
    for r in scan.results:
        counts[r.result] = counts.get(r.result, 0) + 1
    assert counts == {"fail": 5, "pass": 3, "skipped": 2, "notapplicable": 2}
    assert all(r.group_id.startswith("V-") and r.rule_id_src for r in scan.results)


def test_real_overlay_is_one_scan_named_after_the_outermost_profile() -> None:
    [scan] = load_hdf(OVERLAY)
    assert scan.source == str(OVERLAY)
    assert scan.tool.startswith("second-layer-example-inspec-overlay-profile")
    assert len(scan.results) == 13


def test_overlay_impact_comes_from_the_control_that_ran_as_in_heimdall() -> None:
    # An outer layer setting impact 0 on a failing control does not make it not applicable:
    # Heimdall reads everything from the base ("root") control.
    doc = json.loads(OVERLAY.read_text("utf-8"))
    base = next(p for p in doc["profiles"] if any(c.get("results") for c in p["controls"]))
    failing = next(c for c in base["controls"] if c["impact"] and
                   any(r["status"] == "failed" for r in c["results"]))  # fmt: skip
    outer = next(p for p in doc["profiles"] if not p.get("parent_profile"))
    next(c for c in outer["controls"] if c["id"] == failing["id"])["impact"] = 0
    [scan] = loads_hdf(json.dumps(doc))
    assert next(r for r in scan.results if r.group_id == failing["id"]).result == "fail"


def test_release_in_a_wrapped_profile_title_is_found() -> None:
    base = {"name": "base", "parent_profile": "wrap", "title": "DISA RHEL 7 STIG - v2r6",
            "controls": [_control("V-1", 0.5, "passed")]}  # fmt: skip
    wrap = {"name": "wrap", "title": "site overlay", "controls": [{"id": "V-1", "impact": 0.5}]}
    [scan] = loads_hdf(json.dumps({"profiles": [wrap, base]}))
    assert release_id(scan.version, scan.release_info) == (2, 6)
    assert scan.tool.startswith("wrap")


@pytest.mark.parametrize(
    ("base_title", "wrap_title", "expected"),
    [
        ("base profile", "site overlay for v2r7", (2, 7)),  # only the outer layer says
        ("DISA RHEL 7 STIG - v2r6", "site overlay for v2r7", (2, 7)),  # outermost first
    ],
)
def test_release_titles_are_searched_outermost_first(
    base_title: str, wrap_title: str, expected: tuple[int, int]
) -> None:
    base = {"name": "base", "parent_profile": "wrap", "title": base_title,
            "controls": [_control("V-1", 0.5, "passed")]}  # fmt: skip
    wrap = {"name": "wrap", "title": wrap_title, "controls": [{"id": "V-1", "impact": 0.5}]}
    [scan] = loads_hdf(json.dumps({"profiles": [wrap, base]}))
    assert release_id(scan.version, scan.release_info) == expected


def test_real_hdf_of_another_release_is_refused() -> None:
    # Heimdall's RHEL 9 sample says V1R3; the RHEL 9 fixture is V1R1.
    with pytest.raises(ChecklistError, match="V1R3 but the checklist STIG is V1R1"):
        import_results(xccdf.load(RHEL9_V1R1).checklist, load_hdf(RHEL9_V1R3))


def test_real_hdf_imports_by_v_number_into_the_matching_release() -> None:
    checklist = xccdf.load(RHEL9_V1R1).checklist
    checklist.stigs[0].release_info = "Release: 3 Benchmark Date: 24 Apr 2024"  # relabel only
    result = import_results(checklist, load_hdf(RHEL9_V1R3))
    [report] = result.scans
    assert (report.applied, report.matched_by_group_id) == (7, 3)  # V1R1 vs V1R3 revisions
    assert dict(report.not_imported) == {"skipped": 3}
    assert [r.group_id for r in report.unmatched] == ["V-257787"]
    assert report.stig_id == "RHEL_9_TRUNCATED"
    # The release was compared, so differing revisions are expected and not called drift.
    assert not any("different rule revision" in w for w in result.warnings)


def test_unknown_release_with_different_revisions_warns_of_drift() -> None:
    # The real V1R3 sample with its STIGRef tags removed, against the V1R1 checklist: the
    # release can no longer be compared, but 3 of the 10 rule revisions still disagree.
    doc = json.loads(RHEL9_V1R3.read_text("utf-8"))
    for control in doc["profiles"][0]["controls"]:
        control["tags"].pop("STIGRef", None)
    result = import_results(xccdf.load(RHEL9_V1R1).checklist, loads_hdf(json.dumps(doc)))
    assert any("release could not be compared" in w for w in result.warnings)
    assert any("3 of 10 matched rules have a different rule revision" in w for w in result.warnings)


def test_no_drift_warning_when_revisions_agree() -> None:
    result = import_results(_checklist_for("V-1"), loads_hdf(_hdf(_control("V-1", 0.5, "failed"))))
    assert not any("different rule revision" in w for w in result.warnings)


# --- pairing ----------------------------------------------------------------------------------


def test_hdf_pairs_with_the_stig_holding_its_v_numbers() -> None:
    a = Stig("a", "a", "A", "Release: 1", [Rule("V-1", "SV-1r1", "X", "low", Status.NOT_REVIEWED)])
    b = Stig("b", "b", "B", "Release: 1", [Rule("V-9", "SV-9r1", "X", "low", Status.NOT_REVIEWED)])
    checklist = Checklist("t", "i", {}, [a, b])
    [report] = import_results(checklist, loads_hdf(_hdf(_control("V-9", 0.5, "failed")))).scans
    assert (report.stig_id, report.applied) == ("B", 1)


@pytest.mark.parametrize(
    ("controls", "message"),
    [
        (("V-404",), "none of the scan's 1 V-numbers is in the checklist"),
        (("V-1", "V-9"), "spread over 2 checklist STIGs"),
    ],
)
def test_hdf_pairing_refuses_no_stig_or_several(controls: tuple[str, ...], message: str) -> None:
    a = Stig("a", "a", "A", "", [Rule("V-1", "SV-1r1", "X", "low", Status.NOT_REVIEWED)])
    b = Stig("b", "b", "B", "", [Rule("V-9", "SV-9r1", "X", "low", Status.NOT_REVIEWED)])
    doc = _hdf(*(_control(c, 0.5, "failed") for c in controls))
    with pytest.raises(ChecklistError, match=message):
        import_results(Checklist("t", "i", {}, [a, b]), loads_hdf(doc))


def test_hdf_never_checks_the_host_and_says_so() -> None:
    checklist = _checklist_for("V-1")
    checklist.target_data["host_name"] = "web01"
    result = import_results(checklist, loads_hdf(_hdf(_control("V-1", 0.5, "failed"))))
    assert result.scans[0].applied == 1
    assert any("names no host" in w for w in result.warnings)


def test_hdf_without_a_release_warns_instead_of_refusing() -> None:
    result = import_results(_checklist_for("V-1"), loads_hdf(_hdf(_control("V-1", 0.5, "passed"))))
    assert any("release could not be compared" in w for w in result.warnings)
    assert result.checklist.stigs[0].rules[0].status == Status.NOT_A_FINDING


# --- CLI --------------------------------------------------------------------------------------


def test_cli_imports_hdf_json_and_writes_a_schema_valid_checklist(tmp_path: Path) -> None:
    # A schema-valid blank checklist of the scan's rules, built the way the importers build them.
    checklist = tmp_path / "rhel7.cklb"
    [scan] = load_hdf(RHEL7)
    stig_uuid = new_uuid()
    rules = [
        make_rule(new_id=new_uuid, stig_uuid=stig_uuid, group_id=r.group_id,
                  rule_id_src=r.rule_id_src, rule_version="RHEL-07-X", severity="medium")
        for r in scan.results
    ]  # fmt: skip
    stig = make_stig(new_id=new_uuid, stig_uuid=stig_uuid, stig_name="RHEL 7", stig_id="RHEL_7",
                     release_info="Release: 4", rules=rules, version=1)  # fmt: skip
    blank = make_checklist(new_id=new_uuid, title="t", target_data=default_target_data(),
                           stigs=[stig])  # fmt: skip
    cklb.dump(blank, checklist)
    assert _cli("validate", "--schema", str(SCHEMA), str(checklist))[0] == EXIT_OK
    dest = tmp_path / "out.cklb"
    code, out = _cli("import-results", str(checklist), str(RHEL7), "-o", str(dest), "--apply")
    assert code == EXIT_OK
    assert "applied=10" in out and "not_imported: skipped=2" in out
    assert "disa_stig-el7 0.2.0 (HDF, centos 7.6.1810)" in out
    statuses = [r.status for r in cklb.load(dest).stigs[0].rules]
    assert (statuses.count(Status.OPEN), statuses.count(Status.NOT_A_FINDING)) == (5, 3)
    assert statuses.count(Status.NOT_APPLICABLE) == 2
    assert _cli("validate", "--schema", str(SCHEMA), str(dest))[0] == EXIT_OK


def test_cli_hdf_and_xccdf_results_in_one_run(tmp_path: Path) -> None:
    # A checklist with the VPN STIG and a second STIG only an HDF scan covers.
    vpn = cklb.load(VPN_A)
    other = _checklist_for("V-1", release="Release: 4").stigs[0]
    vpn.stigs.append(other)
    vpn.target_data["host_name"] = ""
    checklist = tmp_path / "two.cklb"
    cklb.dump(vpn, checklist)
    hdf = tmp_path / "scan.json"
    hdf.write_text(_hdf(_control("V-1", 0.5, "failed"), title="v1r4"), "utf-8")
    vpn_results = FIXTURES / "xccdf-results" / "Asset_b-VPN_TRUNCATED-V2R5-xccdf.xml"
    code, out = _cli(
        "import-results", str(checklist), str(vpn_results), str(hdf), "-o", str(tmp_path / "o.cklb")
    )
    assert code == EXIT_OK
    assert out.count("applied=") == 2


def test_cli_refuses_a_real_hdf_of_another_release(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _cli("import-results", str(RHEL9_V1R1), str(RHEL9_V1R3), "-o", str(dest), "--apply")
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert "results only apply to the release they scanned" in capsys.readouterr().err
    assert not dest.exists()
