"""CKLB model/IO tests. Fixtures are from the MIT-licensed stig-manager-client-modules repo."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from stigforage import cklb, fsio
from stigforage.model import Checklist, ChecklistError, Rule, Status, Stig, validate

FIXTURES = Path(__file__).parent / "fixtures" / "cklb"
# Fixtures that are intentionally malformed; covered by the failure-path tests below.
BROKEN = {"NoStigsArray.cklb"}
GOOD = sorted(p for p in FIXTURES.glob("*.cklb") if p.name not in BROKEN)


def _minimal(**rule_overrides: Any) -> dict[str, Any]:
    rule = {
        "group_id": "V-1",
        "rule_id": "SV-1r1",
        "rule_version": "X-1",
        "severity": "medium",
        "status": "open",
    }
    rule.update(rule_overrides)
    return {
        "title": "t",
        "id": "i",
        "target_data": {"host_name": "h"},
        "stigs": [
            {"stig_name": "n", "display_name": "d", "stig_id": "S", "release_info": "r",
             "rules": [rule]}
        ],
    }  # fmt: skip


def test_fixture_set_is_not_empty() -> None:
    # Guards against the parametrised tests silently collecting zero cases.
    assert len(GOOD) >= 20


@pytest.mark.parametrize("path", GOOD, ids=lambda p: p.name)
def test_round_trip_preserves_all_data(path: Path) -> None:
    original = json.loads(path.read_text(encoding="utf-8-sig"))
    assert cklb.to_dict(cklb.load(path)) == original


@pytest.mark.parametrize("path", GOOD, ids=lambda p: p.name)
def test_dumps_then_loads_is_stable(path: Path) -> None:
    first = cklb.load(path)
    second = cklb.loads(cklb.dumps(first))
    assert cklb.to_dict(first) == cklb.to_dict(second)


def test_tool_specific_keys_are_preserved() -> None:
    evaluate = [p for p in GOOD if "evaluate-stig" in json.loads(p.read_text("utf-8-sig"))]
    assert evaluate, "expected at least one Evaluate-STIG fixture"
    checklist = cklb.load(evaluate[0])
    assert "evaluate-stig" in checklist.extra
    assert "evaluate-stig" in json.loads(cklb.dumps(checklist))


def test_all_four_statuses_parse() -> None:
    checklist = cklb.load(FIXTURES / "all-possible-results.cklb")
    statuses = {r.status for s in checklist.stigs for r in s.rules}
    assert statuses == set(Status)


def test_stig_without_version_loads_and_stays_without_version() -> None:
    data = _minimal()
    checklist = cklb.loads(json.dumps(data))
    assert checklist.stigs[0].version is None
    assert "version" not in json.loads(cklb.dumps(checklist))["stigs"][0]


def test_absent_optional_rule_keys_are_normalised_on_write() -> None:
    out = json.loads(cklb.dumps(cklb.loads(json.dumps(_minimal()))))
    rule = out["stigs"][0]["rules"][0]
    assert rule["comments"] is None
    assert rule["ccis"] == []
    assert rule["overrides"] == {}


# --- failure paths --------------------------------------------------------------------------


def test_missing_stigs_array_loads_as_empty() -> None:
    """`stigs` is optional in the DISA schema (only title and id are required)."""
    assert cklb.load(FIXTURES / "NoStigsArray.cklb").stigs == []


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("{not json", r"invalid JSON at line 1"),
        ("[]", r"expected object, got list"),
        ('{"stigs": {}}', r"\$\.stigs: expected array"),
        ('{"stigs": [1]}', r"\$\.stigs\[0\]: expected object"),
        ('{"stigs": [], "x": NaN}', r"invalid JSON constant 'NaN'"),
    ],
)
def test_malformed_documents(text: str, match: str) -> None:
    with pytest.raises(ChecklistError, match=match):
        cklb.loads(text)


def test_unknown_status_is_rejected_with_locator() -> None:
    with pytest.raises(ChecklistError, match=r"rules\[0\]\.status: unknown status 'passed'"):
        cklb.loads(json.dumps(_minimal(status="passed")))


@pytest.mark.parametrize("key", ["group_id", "rule_id", "rule_version", "severity", "status"])
def test_missing_required_rule_key(key: str) -> None:
    data = _minimal()
    del data["stigs"][0]["rules"][0][key]
    with pytest.raises(ChecklistError, match=f"missing required key '{key}'"):
        cklb.loads(json.dumps(data))


def test_wrong_type_is_rejected() -> None:
    with pytest.raises(ChecklistError, match=r"group_id: expected string, got int"):
        cklb.loads(json.dumps(_minimal(group_id=5)))


@pytest.mark.parametrize(("value", "kind"), [(True, "bool"), (1.5, "float"), ([2], "list")])
def test_bad_version_types_are_rejected(value: object, kind: str) -> None:
    data = _minimal()
    data["stigs"][0]["version"] = value
    with pytest.raises(ChecklistError, match=rf"version: expected integer or string, got {kind}"):
        cklb.loads(json.dumps(data))


@pytest.mark.parametrize("version", [2, "2"])
def test_version_keeps_its_original_type(version: int | str) -> None:
    data = _minimal()
    data["stigs"][0]["version"] = version
    out = json.loads(cklb.dumps(cklb.loads(json.dumps(data))))
    assert out["stigs"][0]["version"] == version
    assert type(out["stigs"][0]["version"]) is type(version)


def test_non_string_cci_is_rejected() -> None:
    with pytest.raises(ChecklistError, match=r"ccis\[0\]: expected string"):
        cklb.loads(json.dumps(_minimal(ccis=[7])))


def test_load_error_names_the_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.cklb"
    bad.write_text("{oops", encoding="utf-8")
    with pytest.raises(ChecklistError, match=r"bad\.cklb"):
        cklb.load(bad)


def test_non_utf8_file(tmp_path: Path) -> None:
    bad = tmp_path / "latin.cklb"
    bad.write_bytes(b'{"stigs": [], "title": "\xe9"}')
    with pytest.raises(ChecklistError, match="not valid UTF-8"):
        cklb.load(bad)


def test_oversize_file_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fsio, "MAX_BYTES", 10)
    big = tmp_path / "big.cklb"
    big.write_text('{"stigs": []}   ', encoding="utf-8")
    with pytest.raises(ChecklistError, match="over the 10 byte limit"):
        cklb.load(big)


def test_bom_is_tolerated(tmp_path: Path) -> None:
    p = tmp_path / "bom.cklb"
    p.write_bytes(b"\xef\xbb\xbf" + b'{"stigs": []}')
    assert cklb.load(p).stigs == []


# --- writing --------------------------------------------------------------------------------


def test_dump_refuses_to_overwrite(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    dest.write_text("precious", encoding="utf-8")
    checklist = cklb.loads(json.dumps(_minimal()))
    with pytest.raises(FileExistsError, match="--force"):
        cklb.dump(checklist, dest)
    assert dest.read_text(encoding="utf-8") == "precious"


def test_dump_force_overwrites_and_leaves_no_temp_files(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    dest.write_text("old", encoding="utf-8")
    checklist = cklb.loads(json.dumps(_minimal()))
    cklb.dump(checklist, dest, force=True)
    assert cklb.load(dest).stigs[0].stig_id == "S"
    assert [p.name for p in tmp_path.iterdir()] == ["out.cklb"]


def test_failed_write_leaves_destination_untouched_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "out.cklb"
    dest.write_text("keep me", encoding="utf-8")

    def boom(_fd: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", boom)
    checklist = cklb.loads(json.dumps(_minimal()))
    with pytest.raises(OSError, match="disk full"):
        cklb.dump(checklist, dest, force=True)
    assert dest.read_text(encoding="utf-8") == "keep me"
    assert [p.name for p in tmp_path.iterdir()] == ["out.cklb"]


def test_dump_rejects_nan(tmp_path: Path) -> None:
    checklist = cklb.loads(json.dumps(_minimal()))
    checklist.extra["bad"] = float("nan")
    with pytest.raises(ValueError, match="Out of range float"):
        cklb.dump(checklist, tmp_path / "x.cklb")
    assert list(tmp_path.iterdir()) == []


# --- validate -------------------------------------------------------------------------------


def _checklist_with(rules: list[Rule]) -> Checklist:
    stig = Stig(stig_name="n", display_name="d", stig_id="S", release_info="r", rules=rules)
    return Checklist(title="t", id="i", target_data={}, stigs=[stig])


def _rule(**kw: Any) -> Rule:
    base: dict[str, Any] = {
        "group_id": "V-1", "rule_id": "SV-1", "rule_version": "X", "severity": "high",
        "status": Status.OPEN,
    }  # fmt: skip
    base.update(kw)
    return Rule(**base)


def test_validate_clean() -> None:
    assert validate(_checklist_with([_rule(ccis=["CCI-000366"])])) == []


def test_validate_flags_bad_severity_duplicates_and_cci() -> None:
    issues = validate(
        _checklist_with([_rule(severity="critical", ccis=["CCI-12"]), _rule(group_id="V-1")])
    )
    messages = [(i.level, i.message) for i in issues]
    assert ("error", "severity 'critical' is not unknown/low/medium/high") in messages
    assert any(lvl == "warning" and "duplicate group_id 'V-1'" in m for lvl, m in messages)
    assert ("warning", "malformed CCI identifier 'CCI-12'") in messages


def test_validate_warns_on_empty_containers() -> None:
    assert [i.level for i in validate(Checklist("t", "i", {}, []))] == ["warning"]
    assert [i.level for i in validate(_checklist_with([]))] == ["warning"]


@pytest.mark.parametrize("path", GOOD, ids=lambda p: p.name)
def test_real_fixtures_have_no_validation_errors(path: Path) -> None:
    errors = [i for i in validate(cklb.load(path)) if i.level == "error"]
    assert errors == []
