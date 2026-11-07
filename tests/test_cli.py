from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from stigforage import __version__
from stigforage.cli import EXIT_INVALID, EXIT_OK, EXIT_UNREADABLE, run

FIXTURES = Path(__file__).parent / "fixtures" / "cklb"
GOOD = FIXTURES / "Asset_a-multi-stig.cklb"


def _run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = run(list(argv), out=out)
    return code, out.getvalue()


def test_info_reports_counts() -> None:
    code, out = _run("info", str(GOOD))
    assert code == EXIT_OK
    assert "rules:" in out
    assert "not_reviewed=" in out
    assert "host:" in out


def test_info_status_line_lists_every_status() -> None:
    _, out = _run("info", str(FIXTURES / "all-possible-results.cklb"))
    for name in ("not_reviewed", "not_applicable", "open", "not_a_finding"):
        assert f"{name}=1" in out


def test_validate_ok_on_real_fixture() -> None:
    code, out = _run("validate", str(GOOD))
    assert code == EXIT_OK
    assert "error" not in out


def test_missing_file_exits_2_and_keeps_going(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out = _run("info", str(FIXTURES / "does-not-exist.cklb"), str(GOOD))
    assert code == EXIT_UNREADABLE
    assert "rules:" in out  # second file was still processed
    assert "cannot read checklist" in capsys.readouterr().err


def test_malformed_file_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.cklb"
    bad.write_text("{", encoding="utf-8")
    code, _ = _run("validate", str(bad))
    assert code == EXIT_UNREADABLE


def test_validation_error_exits_1(tmp_path: Path) -> None:
    data = json.loads(GOOD.read_text(encoding="utf-8-sig"))
    data["stigs"][0]["rules"][0]["severity"] = "critical"
    p = tmp_path / "sev.cklb"
    p.write_text(json.dumps(data), encoding="utf-8")
    code, out = _run("validate", str(p))
    assert code == EXIT_INVALID
    assert "severity 'critical'" in out


def test_strict_promotes_warnings(tmp_path: Path) -> None:
    p = tmp_path / "empty.cklb"
    p.write_text('{"stigs": []}', encoding="utf-8")
    assert _run("validate", str(p))[0] == EXIT_OK
    assert _run("validate", "--strict", str(p))[0] == EXIT_INVALID


def test_progress_is_logged_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    _run("info", str(GOOD))
    err = capsys.readouterr().err
    assert "reading" in err
    assert "done" in err


def test_help_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        run(["--help"])
    assert exc.value.code == 0
    assert "info" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        run(["--version"])
    assert __version__ in capsys.readouterr().out


def test_no_command_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        run([])
    assert exc.value.code == 2
