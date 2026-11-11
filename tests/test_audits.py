"""`import-results` unit 4: pip-audit and npm audit JSON (ADR 0003 decisions 8 and 9).

Fixtures under fixtures/audit are real output generated for this project (see NOTICE):
pip-audit 2.10.1 on pinned old requests, urllib3 and jinja2 plus a name not on PyPI, and
npm 11.20 audit of old lodash, minimist and mkdirp; each with a clean counterpart.
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
    json_results_kind,
    load_npm_audit,
    load_pip_audit,
    loads_npm_audit,
    loads_pip_audit,
    scan_for_rule,
)
from stigforage.model import ChecklistError, Status
from stigforage.results import import_results

AUDIT = FIXTURES / "audit"
PIP_VULN = AUDIT / "pip-audit-vulnerable.json"
PIP_CLEAN = AUDIT / "pip-audit-clean.json"
NPM_VULN = AUDIT / "npm-audit-vulnerable.json"
NPM_CLEAN = AUDIT / "npm-audit-clean.json"
VPN_XCCDF = FIXTURES / "xccdf" / "U_VPN_SRG_V2R5_Manual-xccdf-truncated.xml"
HDF = FIXTURES / "hdf" / "small_overrides_hdf.json"
TRIVY = FIXTURES / "sarif" / "trivy-alpine-310.sarif"
SCHEMA = FIXTURES / "schema" / "SV3_CKLB_1_0_JSON_SCHEMA.json"
RULE = "V-207184"


def _npm(vulnerabilities: dict[str, Any], version: int = 2) -> str:
    return json.dumps({"auditReportVersion": version, "vulnerabilities": vulnerabilities})


def _advisory(
    severity: str = "high", ghsa: str = "GHSA-aaaa-bbbb-cccc", **kw: Any
) -> dict[str, Any]:
    return {"source": 1, "title": "t", "severity": severity, "range": "<1.0",
            "url": f"https://github.com/advisories/{ghsa}", **kw}  # fmt: skip


def _cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return run(list(argv), out=out), out.getvalue()


# --- pip-audit ------------------------------------------------------------------------------


def test_real_pip_audit_merges_duplicates_and_names_unaudited_packages() -> None:
    [file] = load_pip_audit(PIP_VULN)
    # pip-audit 2.10.1 listed 47 entries for 24 distinct vulnerabilities.
    assert (file.tool, len(file.findings)) == ("pip-audit", 24)
    assert dict(file.not_counted) == {"duplicate": 23, "not audited": 1}
    assert {f.level for f in file.findings} == {"unrated"}  # pip-audit gives no severity
    assert len(file.notes) == 1 and "not-a-real-package-stigforage-test" in file.notes[0]
    first = file.findings[0]
    assert first.rule_id == "PYSEC-2018-28"
    assert first.message == (
        "requests 2.19.1 (CVE-2018-18074, GHSA-x84v-xcm2-53pg); fixed in 2.20.0"
    )


def test_real_clean_pip_audit_has_no_findings() -> None:
    [file] = load_pip_audit(PIP_CLEAN)
    assert (file.findings, dict(file.not_counted), file.notes) == ([], {}, [])


def test_pip_audit_without_a_fix_says_so() -> None:
    doc = {"dependencies": [{"name": "x", "version": "1", "vulns": [{"id": "PYSEC-1"}]}],
           "fixes": []}  # fmt: skip
    [file] = loads_pip_audit(json.dumps(doc))
    assert file.findings[0].message == "x 1; no fixed version listed"


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        ("[]", "expected object"),
        ('{"fixes": []}', "expected array"),
        ('{"dependencies": [{"version": "1"}], "fixes": []}', "dependency has no name"),
        (
            '{"dependencies": [{"name": "x", "vulns": [{}]}], "fixes": []}',
            "vulnerability has no id",
        ),
    ],
)
def test_malformed_pip_audit_is_refused(doc: str, message: str) -> None:
    with pytest.raises(ChecklistError, match=message):
        loads_pip_audit(doc)


# --- npm audit ------------------------------------------------------------------------------


def test_real_npm_audit_counts_advisories_not_packages() -> None:
    [file] = load_npm_audit(NPM_VULN)
    # npm counts 3 vulnerable packages; they carry 10 advisory entries, 8 distinct per package.
    assert (file.tool, len(file.findings)) == ("npm audit", 8)
    assert Counter(f.level for f in file.findings) == {"critical": 2, "high": 3, "moderate": 3}
    assert dict(file.not_counted) == {"duplicate": 2}
    assert file.notes == ["affected through other packages: mkdirp (via minimist)"]
    assert all(f.rule_id.startswith("GHSA-") for f in file.findings)
    assert any(
        f.message == "lodash (<4.17.12): Prototype Pollution in lodash" for f in file.findings
    )


def test_real_clean_npm_audit_has_no_findings() -> None:
    [file] = load_npm_audit(NPM_CLEAN)
    assert (file.findings, file.notes) == ([], [])


def test_npm_duplicate_advisory_keeps_the_most_severe() -> None:
    doc = _npm({"p": {"via": [_advisory("low"), _advisory("critical"), _advisory("moderate")]}})
    [file] = loads_npm_audit(doc)
    assert [f.level for f in file.findings] == ["critical"]
    assert dict(file.not_counted) == {"duplicate": 2}


def test_summary_orders_levels_by_severity_not_alphabet() -> None:
    advisories = [_advisory(sev, f"GHSA-{sev}") for sev in ("info", "low", "moderate", "critical")]
    [file] = loads_npm_audit(_npm({"p": {"via": advisories}}))
    [result] = scan_for_rule(RULE, [file]).results
    assert "4 finding(s) (critical 1, moderate 1, low 1, info 1)" in result.details


def test_npm_advisory_without_a_ghsa_url_keeps_its_npm_source() -> None:
    [file] = loads_npm_audit(_npm({"p": {"via": [_advisory(url="", source=1234)]}}))
    assert file.findings[0].rule_id == "npm-advisory-1234"


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        (_npm({}, version=1), r"expected 2 \(npm 7 or later\), got 1"),
        ('{"auditReportVersion": 2, "vulnerabilities": []}', "expected object"),
        (_npm({"p": {"via": [_advisory("severe")]}}), "unknown severity 'severe'"),
    ],
)
def test_malformed_npm_audit_is_refused(doc: str, message: str) -> None:
    with pytest.raises(ChecklistError, match=message):
        loads_npm_audit(doc)


# --- detecting the format -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "kind"),
    [(PIP_VULN, "pip-audit"), (NPM_VULN, "npm-audit"), (HDF, "hdf"), (TRIVY, "sarif")],
)
def test_json_results_are_identified_by_content(path: Path, kind: str) -> None:
    assert json_results_kind(json.loads(path.read_text("utf-8"))) == kind


def test_unrecognised_json_has_no_kind() -> None:
    assert json_results_kind({"something": "else"}) is None


# --- applying -------------------------------------------------------------------------------


def test_audit_findings_open_the_named_rule() -> None:
    checklist = xccdf.load(VPN_XCCDF).checklist
    scan = scan_for_rule(RULE, load_pip_audit(PIP_VULN) + load_npm_audit(NPM_VULN))
    result = import_results(checklist, [scan])
    rule = next(r for r in result.checklist.stigs[0].rules if r.group_id == RULE)
    assert rule.status == Status.OPEN
    assert rule.finding_details is not None
    assert "pip-audit (" in rule.finding_details and "npm audit (" in rule.finding_details
    assert "not audited: not-a-real-package-stigforage-test" in rule.finding_details


def test_clean_audits_leave_the_status_alone() -> None:
    checklist = xccdf.load(VPN_XCCDF).checklist
    scan = scan_for_rule(RULE, load_pip_audit(PIP_CLEAN) + load_npm_audit(NPM_CLEAN))
    result = import_results(checklist, [scan])
    assert dict(result.scans[0].not_imported) == {"no_findings": 1}
    assert result.checklist == checklist


# --- CLI ------------------------------------------------------------------------------------


def test_cli_audits_with_rule_write_a_schema_valid_checklist(tmp_path: Path) -> None:
    dest = tmp_path / "out.cklb"
    code, out = _cli("import-results", str(VPN_XCCDF), str(PIP_VULN), str(NPM_VULN), str(TRIVY),
                     "--rule", RULE, "-o", str(dest), "--apply")  # fmt: skip
    assert code == EXIT_OK
    assert "applied=1" in out
    rule = next(r for r in cklb.load(dest).stigs[0].rules if r.group_id == RULE)
    assert rule.status == Status.OPEN
    assert rule.finding_details is not None
    assert all(t in rule.finding_details for t in ("pip-audit (", "npm audit (", "Trivy dev ("))
    assert _cli("validate", "--schema", str(SCHEMA), str(dest))[0] == EXIT_OK


def test_cli_audit_without_rule_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = _cli(
        "import-results", str(VPN_XCCDF), str(NPM_VULN), "-o", str(tmp_path / "o.cklb")
    )
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert "SARIF and dependency-audit results need --rule" in capsys.readouterr().err


def test_cli_unrecognised_json_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    odd = tmp_path / "odd.json"
    odd.write_text('{"something": "else"}', "utf-8")
    code, _ = _cli("import-results", str(VPN_XCCDF), str(odd), "-o", str(tmp_path / "o.cklb"))
    assert code == EXIT_UNREADABLE
    assert "not a results format stigforage reads" in capsys.readouterr().err


def test_cli_sarif_with_a_json_extension_is_found_by_content(tmp_path: Path) -> None:
    sarif_json = tmp_path / "trivy-output.json"
    sarif_json.write_bytes(TRIVY.read_bytes())
    code, out = _cli("import-results", str(VPN_XCCDF), str(sarif_json), "--rule", RULE,
                     "-o", str(tmp_path / "o.cklb"))  # fmt: skip
    assert code == EXIT_OK
    assert "applied=1" in out
