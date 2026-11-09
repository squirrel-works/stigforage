"""Rule matching and `diff` command tests."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from conftest import FIXTURES
from stigforage import cklb
from stigforage.cli import EXIT_OK, EXIT_UNREADABLE, run
from stigforage.diff import diff_checklists, diff_stigs, match_rules
from stigforage.model import Checklist, Rule, Status, Stig

VPN_CKL = FIXTURES / "ckl" / "Asset_a-VPN_TRUNCATED-V2R5.ckl"
VPN_XCCDF = FIXTURES / "xccdf" / "U_VPN_SRG_V2R5_Manual-xccdf-truncated.xml"


def _rule(group: str = "V-1", src: str | None = "SV-1r1_rule", **kw: Any) -> Rule:
    extra = kw.pop("extra", {})
    base: dict[str, Any] = {
        "group_id": group,
        "rule_id": (src or "SV-1r1_rule").removesuffix("_rule"),
        "rule_version": "X-1",
        "severity": "medium",
        "status": Status.NOT_REVIEWED,
        "rule_id_src": src,
        "rule_title": "title",
    }
    return Rule(**{**base, **kw}, extra=extra)


def _stig(rules: list[Rule], stig_id: str = "S", release: str = "Release: 1") -> Stig:
    return Stig("n", "n", stig_id, release, rules)


def _checklist(*stigs: Stig) -> Checklist:
    return Checklist("t", "i", {}, list(stigs))


def _cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return run(list(argv), out=out), out.getvalue()


def test_exact_rule_id_src_match() -> None:
    m = match_rules([_rule()], [_rule()])
    assert [by for _, _, by in m.pairs] == ["rule_id_src"]
    assert not m.old_only and not m.new_only and not m.ambiguous


def test_group_id_fallback_when_rule_revision_changes() -> None:
    old, new = _rule(src="SV-1r1_rule"), _rule(src="SV-1r2_rule")
    m = match_rules([old], [new])
    assert [(o, n, by) for o, n, by in m.pairs] == [(old, new, "group_id")]


def test_added_and_removed_rules() -> None:
    m = match_rules([_rule("V-1", "SV-1r1_rule")], [_rule("V-2", "SV-2r1_rule")])
    assert [r.group_id for r in m.old_only] == ["V-1"]
    assert [r.group_id for r in m.new_only] == ["V-2"]
    assert not m.pairs


def test_duplicate_group_id_is_never_guessed() -> None:
    old = [_rule("V-1", "SV-1ar1_rule"), _rule("V-1", "SV-1br1_rule")]
    new = [_rule("V-1", "SV-1ar2_rule"), _rule("V-1", "SV-1br2_rule")]
    m = match_rules(old, new)
    assert not m.pairs
    assert m.ambiguous == ["V-1"]
    assert len(m.old_only) == len(m.new_only) == 2


def test_duplicate_rule_id_src_is_not_matched_by_id() -> None:
    # Same rule id twice on one side: neither copy may claim the counterpart.
    old = [_rule("V-1", "SV-1r1_rule"), _rule("V-2", "SV-1r1_rule")]
    m = match_rules(old, [_rule("V-1", "SV-1r1_rule")])
    assert [by for _, _, by in m.pairs] == ["group_id"]
    assert [r.group_id for r in m.old_only] == ["V-2"]


def test_title_or_cci_similarity_is_not_used() -> None:
    old = _rule("V-1", "SV-1r1_rule", rule_title="same", ccis=["CCI-000001"])
    new = _rule("V-9", "SV-9r1_rule", rule_title="same", ccis=["CCI-000001"])
    assert not match_rules([old], [new]).pairs


def test_rule_without_rule_id_src_matches_on_rule_id() -> None:
    m = match_rules([_rule(src=None)], [_rule(src=None)])
    assert [by for _, _, by in m.pairs] == ["rule_id_src"]


def test_changes_cover_content_and_review_fields() -> None:
    old = _rule(extra={"check_content": "a"})
    new = _rule(
        severity="high",
        status=Status.OPEN,
        comments="c",
        extra={"check_content": "b", "fix_text": "f"},
    )
    names = {c.name for c in diff_stigs(_stig([old]), _stig([new])).rules[0].changes}
    assert names == {"severity", "status", "comments", "check_content", "fix_text"}


def test_none_and_empty_string_are_equal() -> None:
    old = _rule(comments=None, extra={"check_content": None})
    new = _rule(comments="", extra={"check_content": ""})
    assert diff_stigs(_stig([old]), _stig([new])).rules[0].changes == []


def test_rule_revision_bump_is_reported_as_rule_id_change() -> None:
    d = diff_stigs(_stig([_rule(src="SV-1r1_rule")]), _stig([_rule(src="SV-1r2_rule")]))
    assert [c.name for c in d.rules[0].changes] == ["rule_id"]


def test_stigs_are_paired_by_stig_id() -> None:
    old = _checklist(_stig([], "A"), _stig([], "B"))
    new = _checklist(_stig([], "B"), _stig([], "C"))
    d = diff_checklists(old, new)
    assert [s.stig_id for s in d.stigs] == ["B"]
    assert d.old_only_stigs == ["A"]
    assert d.new_only_stigs == ["C"]


@pytest.mark.parametrize("path", [VPN_CKL, VPN_XCCDF])
def test_self_diff_has_no_changes(path: Path) -> None:
    code, out = _cli("diff", str(path), str(path))
    assert code == EXIT_OK
    assert "added=0 removed=0" in out
    assert "~" not in out


def test_cli_diff_reports_review_differences_between_checklist_and_blank() -> None:
    code, out = _cli("diff", str(VPN_CKL), str(VPN_XCCDF))
    assert code == EXIT_OK
    assert "status: not_a_finding -> not_reviewed" in out
    assert "<3 chars> -> <empty>" in out  # review text is summarised by size, not dumped


def test_cli_diff_lists_added_and_removed_rules(tmp_path: Path) -> None:
    checklist = cklb.load(FIXTURES / "cklb" / "Asset_a-multi-stig.cklb")
    fewer = cklb.load(FIXTURES / "cklb" / "Asset_a-multi-stig.cklb")
    dropped = fewer.stigs[0].rules.pop()
    path = tmp_path / "fewer.cklb"
    cklb.dump(fewer, path)
    code, out = _cli("diff", str(path), str(FIXTURES / "cklb" / "Asset_a-multi-stig.cklb"))
    assert code == EXIT_OK
    assert f"+ {dropped.group_id} {dropped.rule_id}" in out
    assert checklist.stigs[0].stig_id in out


def test_cli_diff_unreadable_input_exits_2(tmp_path: Path) -> None:
    code, _ = _cli("diff", str(VPN_CKL), str(tmp_path / "missing.cklb"))
    assert code == EXIT_UNREADABLE
    bad = tmp_path / "x.txt"
    bad.write_text("x", "utf-8")
    assert _cli("diff", str(bad), str(VPN_CKL))[0] == EXIT_UNREADABLE
