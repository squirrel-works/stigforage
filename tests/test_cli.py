from __future__ import annotations

import io
import json
import zipfile
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


# --- convert --------------------------------------------------------------------------------

XCCDF = (
    Path(__file__).parent / "fixtures" / "xccdf" / "U_RHEL_9_STIG_V1R1_Manual-xccdf-truncated.xml"
)
CKL = Path(__file__).parent / "fixtures" / "ckl" / "Asset_a-VPN_TRUNCATED-V2R5.ckl"


def test_convert_is_dry_run_by_default(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _run("convert", str(XCCDF), "-o", str(dest))
    assert code == EXIT_OK
    assert "dry run: would write 1 STIG(s), 10 rule(s)" in out
    assert not dest.exists()


def test_convert_xccdf_to_cklb_with_apply(tmp_path: Path) -> None:
    dest = tmp_path / "blank.cklb"
    code, out = _run("convert", str(XCCDF), "-o", str(dest), "--apply")
    assert code == EXIT_OK
    assert "wrote 1 STIG(s), 10 rule(s)" in out
    _, info = _run("info", str(dest))
    assert "RHEL_9_TRUNCATED" in info
    assert "not_reviewed=10" in info


def test_convert_ckl_to_cklb_and_back(tmp_path: Path) -> None:
    cklb_path = tmp_path / "a.cklb"
    ckl_path = tmp_path / "b.ckl"
    assert _run("convert", str(CKL), "-o", str(cklb_path), "--apply")[0] == EXIT_OK
    assert _run("convert", str(cklb_path), "-o", str(ckl_path), "--apply")[0] == EXIT_OK
    _, original = _run("info", str(CKL))
    _, final = _run("info", str(ckl_path))

    # Same summary apart from the path line. The STIG version ("v2") is lost on the way through
    # CKLB because the DISA schema has no stig-level `version` key, so it is normalised here.
    def norm(text: str) -> list[str]:
        return [ln.replace("  v?  ", "  v2  ") for ln in text.splitlines()[1:]]

    assert norm(original) == norm(final)


def test_convert_never_modifies_the_input(tmp_path: Path) -> None:
    src = tmp_path / "in.ckl"
    src.write_bytes(CKL.read_bytes())
    before = src.read_bytes()
    _run("convert", str(src), "-o", str(tmp_path / "o.cklb"), "--apply")
    assert src.read_bytes() == before


def test_convert_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    dest.write_text("precious", encoding="utf-8")
    code, _ = _run("convert", str(XCCDF), "-o", str(dest), "--apply")
    assert code == EXIT_UNREADABLE
    assert dest.read_text(encoding="utf-8") == "precious"
    code, _ = _run("convert", str(XCCDF), "-o", str(dest), "--apply", "--force")
    assert code == EXIT_OK
    assert dest.read_text(encoding="utf-8") != "precious"


# Regression tests for the V0.1.1 defect fixed in V0.2.2: the dry run reported "would write" and
# exited 0 in cases where --apply then failed.


def test_convert_dry_run_refuses_existing_output_like_apply(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "out.cklb"
    dest.write_text("precious", encoding="utf-8")
    code, out = _run("convert", str(XCCDF), "-o", str(dest))
    assert code == EXIT_UNREADABLE
    assert "would write" not in out
    assert "already exists" in capsys.readouterr().err
    code, out = _run("convert", str(XCCDF), "-o", str(dest), "--force")
    assert code == EXIT_OK
    assert "dry run: would write" in out
    assert dest.read_text(encoding="utf-8") == "precious"


@pytest.mark.parametrize("mode", [[], ["--apply"]], ids=["dry-run", "apply"])
def test_convert_missing_output_directory_fails_in_both_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: list[str]
) -> None:
    dest = tmp_path / "no-such-dir" / "out.cklb"
    code, out = _run("convert", str(XCCDF), "-o", str(dest), *mode)
    assert code == EXIT_UNREADABLE
    assert out == ""
    err = capsys.readouterr().err
    assert "does not exist" in err
    assert ".tmp" not in err  # names the user's path, not mkstemp's temp file
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("mode", [[], ["--apply"]], ids=["dry-run", "apply"])
def test_convert_output_that_is_a_directory_fails_even_with_force(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: list[str]
) -> None:
    dest = tmp_path / "out.cklb"
    dest.mkdir()
    code, out = _run("convert", str(XCCDF), "-o", str(dest), "--force", *mode)
    assert code == EXIT_UNREADABLE
    assert out == ""
    assert "is a directory" in capsys.readouterr().err
    assert dest.is_dir()
    assert list(dest.iterdir()) == []


def test_convert_dry_run_reports_export_warnings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = json.loads(GOOD.read_text(encoding="utf-8-sig"))
    data["stigs"][0]["rules"][0]["overrides"] = {"severity": {"severity": "high", "reason": "r"}}
    src = tmp_path / "ovr.cklb"
    src.write_text(json.dumps(data), encoding="utf-8")
    dest = tmp_path / "out.ckl"
    code, out = _run("convert", str(src), "-o", str(dest))
    assert code == EXIT_OK
    assert "dry run: would write" in out
    assert "rule overrides not written" in capsys.readouterr().err
    assert not dest.exists()


def test_convert_refuses_output_equal_to_input(tmp_path: Path) -> None:
    src = tmp_path / "same.cklb"
    _run("convert", str(XCCDF), "-o", str(src), "--apply")
    before = src.read_bytes()
    code, _ = _run("convert", str(src), "-o", str(src), "--apply", "--force")
    assert code == EXIT_UNREADABLE
    assert src.read_bytes() == before


def test_convert_rejects_unsupported_output_type(tmp_path: Path) -> None:
    code, _ = _run("convert", str(XCCDF), "-o", str(tmp_path / "out.json"), "--apply")
    assert code == EXIT_UNREADABLE


def test_convert_unreadable_input_writes_nothing(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    code, _ = _run("convert", str(tmp_path / "missing.ckl"), "-o", str(dest), "--apply")
    assert code == EXIT_UNREADABLE
    assert not dest.exists()


def test_unsupported_input_type(tmp_path: Path) -> None:
    odd = tmp_path / "x.txt"
    odd.write_text("hi", encoding="utf-8")
    assert _run("info", str(odd))[0] == EXIT_UNREADABLE


def test_import_warnings_are_logged(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    text = CKL.read_text(encoding="utf-8").replace(
        "<SEVERITY_OVERRIDE/>", "<SEVERITY_OVERRIDE>high</SEVERITY_OVERRIDE>", 1
    )
    src = tmp_path / "ovr.ckl"
    src.write_text(text, encoding="utf-8")
    _run("convert", str(src), "-o", str(tmp_path / "o.cklb"))
    assert "severity override not carried over" in capsys.readouterr().err


def test_info_and_validate_accept_xccdf_and_zip(tmp_path: Path) -> None:
    zpath = tmp_path / "s.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.write(XCCDF, "bench-xccdf.xml")
    assert _run("info", str(XCCDF), str(zpath))[0] == EXIT_OK
    assert _run("validate", str(zpath))[0] == EXIT_OK
