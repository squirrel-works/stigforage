"""`merge` policy (ADR 0002 point 2 and addendum) and `merge` command tests."""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import FIXTURES
from stigforage import cklb
from stigforage.cli import EXIT_OK, EXIT_UNREADABLE, run
from stigforage.merge import merge_checklists
from stigforage.model import Checklist, ChecklistError, Rule, Status, Stig

VPN_A = FIXTURES / "cklb" / "Asset_a-VPN_TRUNCATED-V2R5.cklb"
VPN_B = FIXTURES / "cklb" / "Asset_bbbbbbbbb-VPN_TRUNCATED-V2R5.cklb"
VPN_CKL = FIXTURES / "ckl" / "Asset_a-VPN_TRUNCATED-V2R5.ckl"
VPN_XCCDF = FIXTURES / "xccdf" / "U_VPN_SRG_V2R5_Manual-xccdf-truncated.xml"
MULTI_A = FIXTURES / "cklb" / "Asset_a-multi-stig.cklb"


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


def _stig(rules: list[Rule], stig_id: str = "S", release: str = "Release: 1", **kw: Any) -> Stig:
    return Stig("n", "n", stig_id, release, rules, **kw)


def _checklist(*stigs: Stig, host: str = "") -> Checklist:
    return Checklist("t", "i", {"host_name": host}, list(stigs))


def _merge(source_rule: Rule, target_rule: Rule, **kw: Any) -> tuple[Rule, Any]:
    """Merge one rule pair; return the output rule and the STIG report."""
    result = merge_checklists(
        _checklist(_stig([source_rule])), _checklist(_stig([target_rule])), **kw
    )
    return result.checklist.stigs[0].rules[0], result.stigs[0]


def _cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return run(list(argv), out=out), out.getvalue()


# --- the review unit ------------------------------------------------------------------------


def test_empty_target_receives_the_whole_source_unit() -> None:
    src = _rule(
        status=Status.OPEN, comments="c", finding_details="f", overrides={"severity": {"x": "y"}}
    )
    out, report = _merge(src, _rule())
    assert (out.status, out.comments, out.finding_details) == (Status.OPEN, "c", "f")
    assert out.overrides == {"severity": {"x": "y"}}
    assert (report.carried, report.unchanged, report.conflicts) == (1, 0, [])


def test_empty_source_leaves_target_alone() -> None:
    out, report = _merge(_rule(), _rule(status=Status.OPEN, comments="t"))
    assert (out.status, out.comments) == (Status.OPEN, "t")
    assert (report.carried, report.unchanged) == (0, 1)


def test_identical_reviews_are_unchanged_not_conflicts() -> None:
    review: dict[str, Any] = {"status": Status.NOT_A_FINDING, "comments": "same"}
    _, report = _merge(_rule(**review), _rule(**review))
    assert (report.unchanged, report.conflicts) == (1, [])


def test_none_and_empty_string_are_the_same_review() -> None:
    _, report = _merge(
        _rule(status=Status.OPEN, comments=None, finding_details=""),
        _rule(status=Status.OPEN, comments="", finding_details=None),
    )
    assert (report.unchanged, report.conflicts) == (1, [])


def test_different_statuses_conflict_and_target_wins_by_default() -> None:
    out, report = _merge(_rule(status=Status.OPEN), _rule(status=Status.NOT_A_FINDING))
    assert out.status == Status.NOT_A_FINDING
    [conflict] = report.conflicts
    assert (conflict.target_status, conflict.source_status) == (
        Status.NOT_A_FINDING,
        Status.OPEN,
    )
    assert conflict.differs == ("status",)
    assert report.carried == 0


def test_prefer_source_takes_the_source_unit_on_conflict() -> None:
    out, report = _merge(
        _rule(status=Status.OPEN, comments="s"),
        _rule(status=Status.NOT_A_FINDING, comments="t"),
        prefer="source",
    )
    assert (out.status, out.comments) == (Status.OPEN, "s")
    assert len(report.conflicts) == 1


def test_same_status_with_different_comments_is_a_conflict() -> None:
    # The case ADR 0002's original point 2 left undefined: the source text must not vanish.
    out, report = _merge(
        _rule(status=Status.OPEN, comments="source notes"),
        _rule(status=Status.OPEN, comments="target notes"),
    )
    assert out.comments == "target notes"
    assert [c.differs for c in report.conflicts] == [("comments",)]


def test_not_reviewed_target_with_notes_is_not_empty() -> None:
    out, report = _merge(
        _rule(status=Status.OPEN), _rule(status=Status.NOT_REVIEWED, finding_details="wip")
    )
    assert (out.status, out.finding_details) == (Status.NOT_REVIEWED, "wip")
    assert [c.differs for c in report.conflicts] == [("status", "finding_details")]


def test_carried_text_is_never_null() -> None:
    # A status-only review copied into a target: the DISA schema requires strings.
    out, _ = _merge(_rule(status=Status.NOT_APPLICABLE, comments=None), _rule(comments=None))
    assert (out.comments, out.finding_details) == ("", "")


def test_overrides_are_copied_not_shared() -> None:
    src = _rule(status=Status.OPEN, overrides={"severity": {"severity": "high"}})
    out, _ = _merge(src, _rule())
    out.overrides["severity"]["severity"] = "low"
    assert src.overrides == {"severity": {"severity": "high"}}


# --- matching and structure -----------------------------------------------------------------


def test_source_only_rules_with_reviews_are_reported_not_added() -> None:
    reviewed = _rule("V-2", "SV-2r1_rule", status=Status.OPEN)
    blank = _rule("V-3", "SV-3r1_rule")
    result = merge_checklists(
        _checklist(_stig([_rule(), reviewed, blank])), _checklist(_stig([_rule()]))
    )
    assert [r.group_id for r in result.checklist.stigs[0].rules] == ["V-1"]
    assert [r.group_id for r in result.stigs[0].not_carried] == ["V-2"]


def test_ambiguous_group_ids_are_reported_never_guessed() -> None:
    source = [_rule("V-1", "SV-1ar1_rule", status=Status.OPEN), _rule("V-1", "SV-1br1_rule")]
    target = [_rule("V-1", "SV-1ar2_rule"), _rule("V-1", "SV-1br2_rule")]
    result = merge_checklists(_checklist(_stig(source)), _checklist(_stig(target)))
    assert result.stigs[0].ambiguous == ["V-1"]
    assert result.stigs[0].carried == 0
    assert all(r.status == Status.NOT_REVIEWED for r in result.checklist.stigs[0].rules)


def test_group_id_matches_are_counted() -> None:
    _, report = _merge(_rule(src="SV-1r1_rule", status=Status.OPEN), _rule(src="SV-1r2_rule"))
    assert (report.matched_by_group_id, report.carried) == (1, 1)


def test_stigs_only_on_one_side_are_reported_and_target_structure_kept() -> None:
    source = _checklist(_stig([_rule(status=Status.OPEN)], "A"), _stig([], "B"))
    target = _checklist(_stig([_rule()], "A"), _stig([_rule()], "C"))
    result = merge_checklists(source, target)
    assert [s.stig_id for s in result.checklist.stigs] == ["A", "C"]
    assert (result.source_only_stigs, result.target_only_stigs) == (["B"], ["C"])
    assert result.checklist.stigs[1].rules[0].status == Status.NOT_REVIEWED


def test_inputs_are_never_mutated() -> None:
    source = _checklist(_stig([_rule(status=Status.OPEN, comments="s")]))
    target = _checklist(_stig([_rule(status=Status.NOT_A_FINDING, comments="t")]))
    before = (copy.deepcopy(source), copy.deepcopy(target))
    merge_checklists(source, target, prefer="source")
    assert (source, target) == before


# --- release and host checks ----------------------------------------------------------------


def test_different_release_info_is_refused() -> None:
    with pytest.raises(ChecklistError, match="same release"):
        merge_checklists(
            _checklist(_stig([_rule()], release="Release: 1")),
            _checklist(_stig([_rule()], release="Release: 2")),
        )


def test_different_version_is_refused_even_with_same_release_info() -> None:
    with pytest.raises(ChecklistError, match="version 1"):
        merge_checklists(
            _checklist(_stig([_rule()], version=1)), _checklist(_stig([_rule()], version=2))
        )


def test_string_and_int_versions_are_the_same_version() -> None:
    result = merge_checklists(
        _checklist(_stig([_rule()], version="2")), _checklist(_stig([_rule()], version=2))
    )
    assert result.warnings == []


def test_missing_release_info_on_both_sides_is_a_warning() -> None:
    result = merge_checklists(
        _checklist(_stig([_rule()], release="")), _checklist(_stig([_rule()], release=""))
    )
    assert any("could not be verified" in w for w in result.warnings)


@pytest.mark.parametrize(
    ("source_host", "target_host", "warned"),
    [("a", "b", True), ("HOST", "host", False), ("", "b", False), ("a", "", False)],
)
def test_host_mismatch_warns_but_merges(source_host: str, target_host: str, warned: bool) -> None:
    result = merge_checklists(
        _checklist(_stig([_rule(status=Status.OPEN)]), host=source_host),
        _checklist(_stig([_rule()]), host=target_host),
    )
    assert any("host" in w for w in result.warnings) is warned
    assert result.stigs[0].carried == 1


# --- CLI ------------------------------------------------------------------------------------


def test_cli_merge_is_a_dry_run_by_default(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _cli("merge", str(VPN_CKL), str(VPN_XCCDF), "-o", str(dest))
    assert code == EXIT_OK
    assert "VPN_TRUNCATED (Release: 5 Benchmark Date: 07 Jun 2023): carried=" in out
    assert "dry run: would write 1 STIG(s), 10 rule(s)" in out
    assert not dest.exists()


def test_cli_merge_checklist_into_blank_benchmark_carries_every_review(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _cli("merge", str(VPN_CKL), str(VPN_XCCDF), "-o", str(dest), "--apply")
    assert code == EXIT_OK
    assert "conflicts=0" in out
    assert f"wrote 1 STIG(s), 10 rule(s) to {dest}" in out
    merged = cklb.load(dest)
    original = cklb.load(VPN_A)
    review = [(r.group_id, r.status, r.comments or "") for r in original.stigs[0].rules]
    assert [(r.group_id, r.status, r.comments or "") for r in merged.stigs[0].rules] == review


def test_cli_merge_real_conflicts_between_two_hosts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _cli("merge", str(VPN_A), str(VPN_B), "-o", str(dest), "--apply")
    assert code == EXIT_OK  # conflicts are reported, not failures
    assert "  ! V-" in out and "kept target" in out
    assert "differs from TARGET host" in capsys.readouterr().err
    _, preferred = _cli(
        "merge", str(VPN_A), str(VPN_B), "-o", str(tmp_path / "s.cklb"), "--prefer", "source"
    )
    assert "kept source" in preferred


def test_cli_merge_refuses_output_that_is_an_input(tmp_path: Path) -> None:
    source, target = tmp_path / "s.cklb", tmp_path / "t.cklb"
    source.write_bytes(VPN_A.read_bytes())
    target.write_bytes(VPN_B.read_bytes())
    for dest in (source, target):
        code, _ = _cli("merge", str(source), str(target), "-o", str(dest), "--apply", "--force")
        assert code == EXIT_UNREADABLE
    assert source.read_bytes() == VPN_A.read_bytes()
    assert target.read_bytes() == VPN_B.read_bytes()


def test_cli_merge_refuses_a_different_release(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = json.loads(VPN_B.read_text(encoding="utf-8-sig"))
    data["stigs"][0]["release_info"] = "Release: 6 Benchmark Date: 01 Jan 2024"
    target = tmp_path / "newer.cklb"
    target.write_text(json.dumps(data), encoding="utf-8")
    dest = tmp_path / "out.cklb"
    code, out = _cli("merge", str(VPN_A), str(target), "-o", str(dest), "--apply")
    assert code == EXIT_UNREADABLE
    assert out == ""
    assert "use upgrade" in capsys.readouterr().err
    assert not dest.exists()


def test_cli_merge_reports_stigs_on_one_side_only(tmp_path: Path) -> None:
    code, out = _cli("merge", str(MULTI_A), str(VPN_B), "-o", str(tmp_path / "o.cklb"))
    assert code == EXIT_OK
    assert "- STIG only in SOURCE, not merged: RHEL_8_TRUNCATED" in out
    assert "- STIG only in SOURCE, not merged: RHEL_9_TRUNCATED" in out


def test_cli_merge_shares_convert_output_checks(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    dest.write_text("precious", encoding="utf-8")
    code, _ = _cli("merge", str(VPN_A), str(VPN_B), "-o", str(dest))
    assert code == EXIT_UNREADABLE
    assert _cli("merge", str(VPN_A), str(VPN_B), "-o", str(tmp_path / "o.json"))[0] == (
        EXIT_UNREADABLE
    )
    assert dest.read_text(encoding="utf-8") == "precious"


def test_cli_merge_unreadable_input_exits_2(tmp_path: Path) -> None:
    code, _ = _cli(
        "merge", str(tmp_path / "missing.cklb"), str(VPN_B), "-o", str(tmp_path / "o.ckl")
    )
    assert code == EXIT_UNREADABLE
