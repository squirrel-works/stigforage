"""`upgrade` policy (ADR 0002 point 3 and addendum) and `upgrade` command tests.

No two consecutive real DISA releases of one STIG are available, so the CLI tests build a
synthetic "next release" from the truncated VPN SRG V2R5 benchmark.
"""

from __future__ import annotations

import copy
import io
from pathlib import Path
from typing import Any

import pytest

from conftest import FIXTURES
from stigforage import ckl, cklb, xccdf
from stigforage.cli import EXIT_OK, EXIT_UNREADABLE, run
from stigforage.merge import is_empty_review
from stigforage.model import Checklist, ChecklistError, Rule, Status, Stig
from stigforage.upgrade import SeverityChange, upgrade_checklist

VPN_CKL = FIXTURES / "ckl" / "Asset_a-VPN_TRUNCATED-V2R5.ckl"
VPN_XCCDF = FIXTURES / "xccdf" / "U_VPN_SRG_V2R5_Manual-xccdf-truncated.xml"
VPN_B = FIXTURES / "cklb" / "Asset_bbbbbbbbb-VPN_TRUNCATED-V2R5.cklb"
MULTI_A = FIXTURES / "cklb" / "Asset_a-multi-stig.cklb"
SCHEMA = FIXTURES / "schema" / "SV3_CKLB_1_0_JSON_SCHEMA.json"
NEW_RELEASE = "Release: 6 Benchmark Date: 01 Jan 2024"


def _rule(group: str = "V-1", src: str = "SV-1r1_rule", check: str = "check", **kw: Any) -> Rule:
    base: dict[str, Any] = {
        "group_id": group,
        "rule_id": src.removesuffix("_rule"),
        "rule_version": "X-1",
        "severity": "medium",
        "status": Status.NOT_REVIEWED,
        "rule_id_src": src,
    }
    return Rule(**{**base, **kw}, extra={"check_content": check})


def _stig(rules: list[Rule], stig_id: str = "S", release: str = "Release: 1", **kw: Any) -> Stig:
    return Stig("n", "n", stig_id, release, rules, **kw)


def _checklist(*stigs: Stig, **kw: Any) -> Checklist:
    return Checklist(kw.get("title", "t"), kw.get("id", "i"), kw.get("target", {}), list(stigs))


def _upgrade(old_rule: Rule, new_rule: Rule, **kw: Any) -> tuple[Rule, Any]:
    """Upgrade one rule from Release 1 to Release 2; return the output rule and the report."""
    result = upgrade_checklist(
        _checklist(_stig([old_rule], release="Release: 1")),
        _checklist(_stig([new_rule], release="Release: 2")),
        **kw,
    )
    return result.checklist.stigs[0].rules[0], result.stigs[0]


def _cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return run(list(argv), out=out), out.getvalue()


# --- carrying and downgrading ---------------------------------------------------------------


def test_unchanged_check_text_carries_the_whole_review() -> None:
    old = _rule(
        status=Status.OPEN, comments="c", finding_details="f", overrides={"severity": {"x": "y"}}
    )
    out, rep = _upgrade(old, _rule())
    assert (out.status, out.comments, out.finding_details) == (Status.OPEN, "c", "f")
    assert out.overrides == {"severity": {"x": "y"}}
    assert (rep.carried, rep.downgraded, rep.check_changes) == (1, 0, [])


def test_reflowed_check_text_is_not_a_change() -> None:
    out, rep = _upgrade(
        _rule(status=Status.OPEN, check="Verify  the\n  setting.\n"),
        _rule(check="Verify the setting."),
    )
    assert out.status == Status.OPEN
    assert (rep.carried, rep.downgraded) == (1, 0)


def test_changed_check_text_downgrades_and_prepends_a_note() -> None:
    old = _rule(
        status=Status.OPEN,
        comments="my notes",
        finding_details="evidence",
        overrides={"severity": {"x": "y"}},
    )
    out, rep = _upgrade(old, _rule(check="a different check"))
    assert out.status == Status.NOT_REVIEWED
    assert out.comments == (
        "[stigforage upgrade] Status was open under Release: 1; the check text changed in "
        "Release: 2. Re-review required.\n\nmy notes"
    )
    assert (out.finding_details, out.overrides) == ("evidence", {"severity": {"x": "y"}})
    assert (rep.carried, rep.downgraded) == (0, 1)
    assert [(c.old_status, c.action) for c in rep.check_changes] == [(Status.OPEN, "downgraded")]


def test_downgrade_note_alone_when_there_were_no_comments() -> None:
    out, _ = _upgrade(_rule(status=Status.NOT_A_FINDING, comments=None), _rule(check="new"))
    assert out.comments is not None
    assert out.comments.startswith("[stigforage upgrade] Status was not_a_finding")
    assert "\n" not in out.comments


def test_keep_status_on_change_keeps_status_and_adds_no_note() -> None:
    out, rep = _upgrade(
        _rule(status=Status.OPEN, comments="c"), _rule(check="new"), keep_status_on_change=True
    )
    assert (out.status, out.comments) == (Status.OPEN, "c")
    assert (rep.carried, rep.downgraded) == (1, 0)
    assert [c.action for c in rep.check_changes] == ["kept"]


def test_not_reviewed_rule_with_notes_gets_no_note() -> None:
    out, rep = _upgrade(_rule(comments="wip"), _rule(check="new"))
    assert (out.status, out.comments) == (Status.NOT_REVIEWED, "wip")
    assert [c.action for c in rep.check_changes] == ["was_not_reviewed"]


def test_old_rule_without_check_text_is_treated_as_changed() -> None:
    out, rep = _upgrade(_rule(status=Status.NOT_A_FINDING, check=""), _rule(check="something"))
    assert out.status == Status.NOT_REVIEWED
    assert out.comments is not None
    assert "the old checklist has no check text to compare with Release: 2" in out.comments
    assert rep.downgraded == 1


def test_no_check_text_on_either_side_still_cannot_be_compared() -> None:
    # Two empty texts are not evidence that the check is unchanged across releases.
    out, rep = _upgrade(_rule(status=Status.OPEN, check=""), _rule(check=""))
    assert out.status == Status.NOT_REVIEWED
    assert rep.downgraded == 1


def test_severity_change_is_reported_but_never_downgrades() -> None:
    out, rep = _upgrade(_rule(status=Status.OPEN), _rule(severity="high"))
    assert out.status == Status.OPEN
    assert out.severity == "high"  # the new release's severity is the one in force
    assert rep.severity_changes == [SeverityChange("V-1", "SV-1r1", "medium", "high")]


def test_blank_old_rule_carries_nothing() -> None:
    out, rep = _upgrade(_rule(), _rule(check="new"))
    assert is_empty_review(out)
    assert (rep.carried, rep.downgraded, rep.check_changes) == (0, 0, [])


def test_revision_bump_matches_by_group_id_and_carries() -> None:
    out, rep = _upgrade(_rule(src="SV-1r1_rule", status=Status.OPEN), _rule(src="SV-1r2_rule"))
    assert out.status == Status.OPEN
    assert (rep.matched_by_group_id, rep.carried) == (1, 1)


# --- structure ------------------------------------------------------------------------------


def test_added_removed_and_lost_rules() -> None:
    old = [
        _rule("V-1", "SV-1r1_rule", status=Status.OPEN),
        _rule("V-2", "SV-2r1_rule", status=Status.NOT_A_FINDING),
        _rule("V-3", "SV-3r1_rule"),
    ]
    new = [_rule("V-1", "SV-1r1_rule"), _rule("V-4", "SV-4r1_rule")]
    result = upgrade_checklist(_checklist(_stig(old)), _checklist(_stig(new, release="R2")))
    rep = result.stigs[0]
    assert [r.group_id for r in rep.added] == ["V-4"]
    assert rep.removed == 2
    assert [r.group_id for r in rep.lost] == ["V-2"]  # V-3 had no review to lose
    assert [r.group_id for r in result.checklist.stigs[0].rules] == ["V-1", "V-4"]


def test_ambiguous_group_ids_are_reported_never_guessed() -> None:
    old = [_rule("V-1", "SV-1ar1_rule", status=Status.OPEN), _rule("V-1", "SV-1br1_rule")]
    new = [_rule("V-1", "SV-1ar2_rule"), _rule("V-1", "SV-1br2_rule")]
    result = upgrade_checklist(_checklist(_stig(old)), _checklist(_stig(new, release="R2")))
    assert result.stigs[0].ambiguous == ["V-1"]
    assert all(is_empty_review(r) for r in result.checklist.stigs[0].rules)


def test_output_takes_structure_from_new_and_asset_data_from_old() -> None:
    old = _checklist(
        _stig([_rule(status=Status.OPEN, uuid="old-rule")], uuid="old-stig"),
        title="old title",
        id="old-id",
        target={"host_name": "host1"},
    )
    new = _checklist(
        _stig(
            [_rule(uuid="new-rule", rule_title="new title")], release="Release: 2", uuid="new-stig"
        ),
        title="benchmark",
        id="new-id",
    )
    out = upgrade_checklist(old, new).checklist
    assert (out.title, out.id, out.target_data) == ("old title", "old-id", {"host_name": "host1"})
    stig = out.stigs[0]
    assert (stig.uuid, stig.release_info) == ("new-stig", "Release: 2")
    assert (stig.rules[0].uuid, stig.rules[0].rule_title) == ("new-rule", "new title")
    assert stig.rules[0].status == Status.OPEN


def test_stigs_missing_from_new_carry_over_and_new_only_stigs_are_not_added() -> None:
    b = _stig([_rule(status=Status.OPEN)], "B")
    old = _checklist(b, _stig([_rule(status=Status.OPEN)], "A"))
    new = _checklist(_stig([_rule()], "A", release="R2"), _stig([_rule()], "C", release="R2"))
    result = upgrade_checklist(old, new)
    assert [s.stig_id for s in result.checklist.stigs] == ["B", "A"]  # OLD's order
    assert result.checklist.stigs[0] == b
    assert (result.unchanged_stigs, result.new_only_stigs) == (["B"], ["C"])


def test_reviewed_new_benchmark_is_refused() -> None:
    reviewed = _checklist(_stig([_rule(comments="someone's notes")], release="R2"))
    with pytest.raises(ChecklistError, match="use merge"):
        upgrade_checklist(_checklist(_stig([_rule()])), reviewed)


def test_same_release_carries_every_review() -> None:
    result = upgrade_checklist(
        _checklist(_stig([_rule(status=Status.OPEN, check="a")], release="Release: 1")),
        _checklist(_stig([_rule(check="b")], release="Release: 1")),
    )
    rep = result.stigs[0]
    assert rep.same_release
    assert (rep.carried, rep.downgraded) == (1, 0)
    assert result.checklist.stigs[0].rules[0].status == Status.OPEN


def test_same_release_needs_release_info_to_be_claimed() -> None:
    result = upgrade_checklist(
        _checklist(_stig([_rule()], release="")), _checklist(_stig([_rule()], release=""))
    )
    assert not result.stigs[0].same_release


def test_inputs_are_never_mutated_and_output_is_reproducible() -> None:
    old = _checklist(_stig([_rule(status=Status.OPEN, comments="c")]))
    new = _checklist(_stig([_rule(check="changed")], release="Release: 2"))
    before = (copy.deepcopy(old), copy.deepcopy(new))
    first = upgrade_checklist(old, new).checklist
    assert (old, new) == before
    assert upgrade_checklist(old, new).checklist == first


# --- CLI ------------------------------------------------------------------------------------


def _next_release(tmp_path: Path) -> Path:
    """A blank "Release 6" of the VPN SRG with one change of each kind (see the assertions)."""
    checklist = xccdf.load(VPN_XCCDF).checklist
    stig = checklist.stigs[0]
    stig.release_info = NEW_RELEASE
    by_group = {r.group_id: r for r in stig.rules}
    by_group["V-207184"].extra["check_content"] = "  ".join(
        by_group["V-207184"].extra["check_content"].split()
    )  # reflowed only
    by_group["V-207185"].extra["check_content"] = "A rewritten check."  # open -> downgraded
    by_group["V-207186"].severity = "high"  # was medium
    by_group["V-207187"].extra["check_content"] = "Another rewrite."  # not_reviewed with notes
    bumped = by_group["V-207190"]
    bumped.rule_id_src = "SV-207190r999999_rule"
    bumped.rule_id = "SV-207190r999999"
    added = copy.deepcopy(by_group["V-207192"])
    added.group_id, added.rule_id_src, added.rule_id = (
        "V-999999",
        "SV-999999r1_rule",
        "SV-999999r1",
    )
    stig.rules = [r for r in stig.rules if r.group_id not in {"V-207191", "V-207193"}]
    stig.rules.append(added)
    path = tmp_path / "vpn-r6.cklb"
    cklb.dump(checklist, path)
    return path


def test_cli_upgrade_is_a_dry_run_by_default(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _cli("upgrade", str(VPN_CKL), str(_next_release(tmp_path)), "-o", str(dest))
    assert code == EXIT_OK
    assert f"VPN_TRUNCATED: Release: 5 Benchmark Date: 07 Jun 2023 -> {NEW_RELEASE}" in out
    assert "dry run: would write" in out
    assert not dest.exists()


def test_cli_upgrade_applies_every_rule_of_the_policy(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _cli(
        "upgrade", str(VPN_CKL), str(_next_release(tmp_path)), "-o", str(dest), "--apply"
    )
    assert code == EXIT_OK
    assert "matched=8 carried=6 downgraded=1 added=1 removed=2 matched_by_group_id=1" in out, out
    assert "v V-207185 SV-207185r608988: check text changed; open -> not_reviewed" in out
    assert "check text changed; status was not_reviewed; notes carried" in out
    assert "^ V-207186 SV-207186r608988: severity medium -> high (status kept)" in out
    assert "+ V-999999 SV-999999r1" in out
    assert "- V-207191 SV-207191r803418: open review lost" in out
    assert "V-207193" not in out  # removed, but it held no review

    status = {r.group_id: r.status for r in cklb.load(dest).stigs[0].rules}
    old = {r.group_id: r.status for r in ckl.load(VPN_CKL).checklist.stigs[0].rules}
    assert status["V-207185"] == Status.NOT_REVIEWED
    for kept in ("V-207184", "V-207186", "V-207188", "V-207190"):
        assert status[kept] == old[kept] != Status.NOT_REVIEWED
    assert status["V-999999"] == Status.NOT_REVIEWED
    assert _cli("validate", "--schema", str(SCHEMA), str(dest))[0] == EXIT_OK


def test_cli_upgrade_keep_status_on_change(tmp_path: Path) -> None:
    code, out = _cli(
        "upgrade",
        str(VPN_CKL),
        str(_next_release(tmp_path)),
        "-o",
        str(tmp_path / "o.cklb"),
        "--keep-status-on-change",
    )
    assert code == EXIT_OK
    assert "downgraded=0" in out
    assert "open kept (--keep-status-on-change)" in out


def test_cli_upgrade_to_the_same_release(tmp_path: Path) -> None:
    reviewed = sum(not is_empty_review(r) for r in ckl.load(VPN_CKL).checklist.stigs[0].rules)
    code, out = _cli("upgrade", str(VPN_CKL), str(VPN_XCCDF), "-o", str(tmp_path / "o.cklb"))
    assert code == EXIT_OK
    assert "already at this release" in out
    assert f"carried={reviewed} downgraded=0 added=0 removed=0" in out


def test_cli_upgrade_refuses_a_reviewed_new_benchmark(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "o.cklb"
    code, out = _cli("upgrade", str(VPN_CKL), str(VPN_B), "-o", str(dest), "--apply")
    assert code == EXIT_UNREADABLE
    assert out == ""
    assert "use merge" in capsys.readouterr().err
    assert not dest.exists()


def test_cli_upgrade_multi_stig_checklist(tmp_path: Path) -> None:
    dest = tmp_path / "o.cklb"
    code, out = _cli(
        "upgrade", str(MULTI_A), str(_next_release(tmp_path)), "-o", str(dest), "--apply"
    )
    assert code == EXIT_OK
    assert "= STIG not in NEW_BENCHMARK, carried over unchanged: RHEL_8_TRUNCATED" in out
    assert "= STIG not in NEW_BENCHMARK, carried over unchanged: RHEL_9_TRUNCATED" in out
    stigs = cklb.load(dest).stigs
    assert [s.stig_id for s in stigs] == [s.stig_id for s in cklb.load(MULTI_A).stigs]
    assert next(s for s in stigs if s.stig_id == "VPN_TRUNCATED").release_info == NEW_RELEASE


def test_cli_upgrade_output_checks_and_unreadable_input(tmp_path: Path) -> None:
    old = tmp_path / "old.ckl"
    old.write_bytes(VPN_CKL.read_bytes())
    new = _next_release(tmp_path)
    for dest in (old, new):
        assert _cli("upgrade", str(old), str(new), "-o", str(dest), "--apply", "--force")[0] == (
            EXIT_UNREADABLE
        )
    assert old.read_bytes() == VPN_CKL.read_bytes()
    missing = tmp_path / "missing.ckl"
    assert _cli("upgrade", str(missing), str(new), "-o", str(tmp_path / "o.cklb"))[0] == (
        EXIT_UNREADABLE
    )
