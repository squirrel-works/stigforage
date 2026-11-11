"""Tool findings with no STIG identifiers, attached to a rule the user names (`--rule`).

Unit 3 reads SARIF 2.1.0, which Flawfinder, Trivy, Grype, OSV-Scanner and many others write.
Policy (ADR 0003 decision 8): every findings file in a run is evidence for the one checklist
rule named with `--rule`. Any finding makes that rule `open`; no findings leaves its status
alone, because a clean scan does not prove compliance. No mapping file. The result goes
through the same pairing and conflict rules as any scan; neither release nor host is
recorded, so both are warnings.

What counts as a finding (SARIF 2.1.0): a result whose `kind` is `fail` (the default), that is
not suppressed (a suppression with status `accepted` or no status), and whose `baselineState`
is not `absent` (gone since the baseline). Every `level` counts, `note` included. Results not
counted are tallied by reason. Real files from Flawfinder, Trivy and Grype use none of `kind`,
`suppressions` or `baselineState`, so every result there is a finding.

Unit 4 reads dependency audits the same way (decision 9):
- pip-audit JSON: one finding per package, version and vulnerability id. Real pip-audit 2.10
  output lists most vulnerabilities twice (47 entries, 24 distinct ids), so duplicates are
  merged and counted. pip-audit gives no severity: the level is `unrated`. A package it could
  not audit (`skip_reason`) is named in the summary, since it is a gap in the evidence.
- npm audit JSON (npm 7+, report version 2): one finding per package and advisory. An
  advisory listed twice for one package (real output does, with different version ranges) is
  merged, keeping the most severe. Levels are npm's own (critical, high, moderate, low, info).
  Packages affected only through another vulnerable package are named in the summary.

Trust boundary: findings files are untrusted; malformed content raises ChecklistError with a
locator.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

from stigforage.fsio import read_limited
from stigforage.model import ChecklistError
from stigforage.results import RuleResult, Scan

__all__ = [
    "MAX_LISTED",
    "Finding",
    "FindingsFile",
    "is_v_number",
    "json_results_kind",
    "load_npm_audit",
    "load_pip_audit",
    "load_sarif",
    "loads_npm_audit",
    "loads_pip_audit",
    "loads_sarif",
    "parse_json",
    "scan_for_rule",
]

# Findings listed per file in the finding details; the counts above the list stay complete.
# A dependency scan can report hundreds of CVEs, and the details are meant to be read.
MAX_LISTED = 50
_LEVELS = frozenset({"error", "warning", "note", "none"})
_V_NUMBER_RE = re.compile(r"^V-\d+$")
# Summary order across tools' vocabularies, most severe first; anything else follows, sorted.
_LEVEL_ORDER = ("critical", "high", "error", "moderate", "warning", "low", "note", "info",
                "none", "unrated")  # fmt: skip
_NPM_SEVERITY = {"info": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    rule_id: str  # the tool's id, e.g. CVE-2019-1549, FF1014, PYSEC-2018-28, GHSA-...
    level: str  # in the tool's own words: SARIF levels, npm severities, or "unrated"
    message: str  # collapsed to one line
    location: str  # "path:line", or ""


@dataclass
class FindingsFile:
    source: str
    tool: str
    findings: list[Finding]
    not_counted: Counter[str] = field(default_factory=Counter)  # by reason
    notes: list[str] = field(default_factory=list)  # evidence gaps worth a line of their own


def is_v_number(text: str) -> bool:
    return _V_NUMBER_RE.match(text) is not None


def _fail(path: str, message: str) -> NoReturn:
    raise ChecklistError(f"{path}: {message}")


def _reject_constant(name: str) -> NoReturn:
    raise ChecklistError(f"$: invalid JSON constant {name!r}")


def _dict(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, f"expected object, got {type(value).__name__}")
    return value


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(path, f"expected array, got {type(value).__name__}")
    return value


def _str(value: Any) -> str:
    return " ".join(value.split()) if isinstance(value, str) else ""


def _location(result: dict[str, Any]) -> str:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return ""
    physical = locations[0].get("physicalLocation")
    if not isinstance(physical, dict):
        return ""
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    uri = _str(artifact.get("uri")) if isinstance(artifact, dict) else ""
    line = region.get("startLine") if isinstance(region, dict) else None
    return f"{uri}:{line}" if uri and isinstance(line, int) else uri


def _not_counted(result: dict[str, Any]) -> str | None:
    """Why a result is not a finding, or None when it is one."""
    kind = _str(result.get("kind")) or "fail"
    if kind != "fail":
        return f"kind {kind}"
    suppressions = result.get("suppressions")
    if isinstance(suppressions, list) and any(
        isinstance(s, dict) and _str(s.get("status")) in ("", "accepted") for s in suppressions
    ):
        return "suppressed"
    if _str(result.get("baselineState")) == "absent":
        return "absent from this run"
    return None


def _run(run: dict[str, Any], path: str, source: str) -> FindingsFile:
    driver = _dict(_dict(run.get("tool"), f"{path}.tool").get("driver"), f"{path}.tool.driver")
    name = _str(driver.get("name"))
    if not name:
        _fail(f"{path}.tool.driver", "missing name")
    version = _str(driver.get("semanticVersion")) or _str(driver.get("version"))
    rules = [r for r in driver.get("rules", []) if isinstance(r, dict)]
    by_id = {_str(r.get("id")): r for r in rules}
    file = FindingsFile(source, f"{name} {version}".strip(), [])
    for i, raw in enumerate(_list(run.get("results", []), f"{path}.results")):
        result = _dict(raw, f"{path}.results[{i}]")
        reason = _not_counted(result)
        if reason:
            file.not_counted[reason] += 1
            continue
        rule_id = _str(result.get("ruleId"))
        index = result.get("ruleIndex")
        if not rule_id and isinstance(index, int) and 0 <= index < len(rules):
            rule_id = _str(rules[index].get("id"))
        rule = by_id.get(rule_id, {})
        # SARIF 2.1.0: an absent level falls back to the rule's default, then to "warning".
        default = rule.get("defaultConfiguration")
        level = _str(result.get("level")) or (
            _str(default.get("level")) if isinstance(default, dict) else ""
        )
        level = level or "warning"
        if level not in _LEVELS:
            _fail(f"{path}.results[{i}].level", f"unknown level {level!r}")
        message = result.get("message")
        text = _str(message.get("text")) if isinstance(message, dict) else ""
        file.findings.append(
            Finding(rule_id or "(no rule id)", level, text or "(no message)", _location(result))
        )
    return file


def parse_json(text: str, source: str) -> dict[str, Any]:
    """Parse untrusted JSON text that must be an object."""
    try:
        return _dict(json.loads(text, parse_constant=_reject_constant), source)
    except json.JSONDecodeError as exc:
        raise ChecklistError(
            f"{source}: invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc


def json_results_kind(doc: dict[str, Any]) -> str | None:
    """Which results format a JSON document is, from its top-level keys, or None."""
    if "runs" in doc and "version" in doc:
        return "sarif"
    if "profiles" in doc:
        return "hdf"
    if "auditReportVersion" in doc:
        return "npm-audit"
    if isinstance(doc.get("dependencies"), list) and "fixes" in doc:
        return "pip-audit"
    return None


def loads_sarif(text: str, *, source: str = "SARIF") -> list[FindingsFile]:
    """Parse SARIF 2.1.0 JSON into one FindingsFile per run (per tool)."""
    doc = parse_json(text, source)
    if doc.get("version") != "2.1.0":
        _fail(f"{source}.version", f"expected SARIF 2.1.0, got {doc.get('version')!r}")
    runs = _list(doc.get("runs"), f"{source}.runs")
    if not runs:
        _fail(f"{source}.runs", "no runs")
    return [_run(_dict(r, f"{source}.runs[{i}]"), f"{source}.runs[{i}]", source)
            for i, r in enumerate(runs)]  # fmt: skip


def loads_pip_audit(text: str, *, source: str = "pip-audit") -> list[FindingsFile]:
    """Parse `pip-audit -f json` output (a `dependencies` list and a `fixes` list)."""
    doc = parse_json(text, source)
    file = FindingsFile(source, "pip-audit", [])
    seen: set[tuple[str, str, str]] = set()
    for i, raw in enumerate(_list(doc.get("dependencies"), f"{source}.dependencies")):
        path = f"{source}.dependencies[{i}]"
        dep = _dict(raw, path)
        name, version = _str(dep.get("name")), _str(dep.get("version"))
        if not name:
            _fail(path, "dependency has no name")
        if "skip_reason" in dep:
            file.not_counted["not audited"] += 1
            file.notes.append(f"not audited: {name}: {_str(dep.get('skip_reason'))}")
            continue
        for j, vraw in enumerate(_list(dep.get("vulns", []), f"{path}.vulns")):
            vuln = _dict(vraw, f"{path}.vulns[{j}]")
            vid = _str(vuln.get("id"))
            if not vid:
                _fail(f"{path}.vulns[{j}]", "vulnerability has no id")
            if (name, version, vid) in seen:
                file.not_counted["duplicate"] += 1
                continue
            seen.add((name, version, vid))
            aliases = [_str(a) for a in vuln.get("aliases", []) if _str(a)]
            fixes = [_str(f) for f in vuln.get("fix_versions", []) if _str(f)]
            message = f"{name} {version}".strip()
            message += f" ({', '.join(aliases)})" if aliases else ""
            message += f"; fixed in {', '.join(fixes)}" if fixes else "; no fixed version listed"
            file.findings.append(Finding(vid, "unrated", message, ""))
    return [file]


def _advisory_id(advisory: dict[str, Any]) -> str:
    url = _str(advisory.get("url"))
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    return tail if tail.startswith("GHSA-") else f"npm-advisory-{advisory.get('source')}"


def loads_npm_audit(text: str, *, source: str = "npm audit") -> list[FindingsFile]:
    """Parse `npm audit --json` output from npm 7 or later (auditReportVersion 2)."""
    doc = parse_json(text, source)
    if doc.get("auditReportVersion") != 2:
        _fail(
            f"{source}.auditReportVersion",
            f"expected 2 (npm 7 or later), got {doc.get('auditReportVersion')!r}",
        )
    vulnerabilities = _dict(doc.get("vulnerabilities"), f"{source}.vulnerabilities")
    file = FindingsFile(source, "npm audit", [])
    best: dict[tuple[str, str], Finding] = {}
    for package, raw in vulnerabilities.items():
        path = f"{source}.vulnerabilities.{package}"
        entry = _dict(raw, path)
        via = _list(entry.get("via", []), f"{path}.via")
        through = [_str(v) for v in via if isinstance(v, str)]
        if through and not any(isinstance(v, dict) for v in via):
            file.notes.append(
                f"affected through other packages: {package} (via {', '.join(through)})"
            )
        for k, advisory in enumerate(v for v in via if isinstance(v, dict)):
            severity = _str(advisory.get("severity"))
            if severity not in _NPM_SEVERITY:
                _fail(f"{path}.via[{k}].severity", f"unknown severity {advisory.get('severity')!r}")
            finding = Finding(
                _advisory_id(advisory),
                severity,
                f"{package} ({_str(advisory.get('range')) or '?'}): {_str(advisory.get('title'))}",
                "",
            )
            key = (package, finding.rule_id)
            if key in best:
                file.not_counted["duplicate"] += 1
                if _NPM_SEVERITY[severity] <= _NPM_SEVERITY[best[key].level]:
                    continue
            best[key] = finding
    file.findings = list(best.values())
    return [file]


def _load(path: Path, parse: Callable[..., list[FindingsFile]]) -> list[FindingsFile]:
    data = read_limited(path)
    try:
        return parse(data.decode("utf-8-sig"), source=str(path))
    except UnicodeDecodeError as exc:
        raise ChecklistError(f"{path}: not valid UTF-8: {exc.reason}") from exc


def load_sarif(path: Path) -> list[FindingsFile]:
    """Read a SARIF file. Raises ChecklistError, OSError."""
    return _load(path, loads_sarif)


def load_pip_audit(path: Path) -> list[FindingsFile]:
    """Read a pip-audit JSON file. Raises ChecklistError, OSError."""
    return _load(path, loads_pip_audit)


def load_npm_audit(path: Path) -> list[FindingsFile]:
    """Read an npm audit JSON file. Raises ChecklistError, OSError."""
    return _load(path, loads_npm_audit)


def _summary(file: FindingsFile) -> list[str]:
    levels = Counter(f.level for f in file.findings)
    order = [k for k in _LEVEL_ORDER if k in levels] + sorted(set(levels) - set(_LEVEL_ORDER))
    by_level = ", ".join(f"{k} {levels[k]}" for k in order)
    head = f"{file.tool} ({file.source}): {len(file.findings)} finding(s)"
    head += f" ({by_level})" if by_level else ""
    if file.not_counted:
        head += "; not counted: " + ", ".join(
            f"{k} {v}" for k, v in sorted(file.not_counted.items())
        )
    lines = [head, *(f"  {note}" for note in file.notes)]
    for f in file.findings[:MAX_LISTED]:
        lines.append(
            f"  {f.rule_id} [{f.level}] {f.message}" + (f" ({f.location})" if f.location else "")
        )
    if len(file.findings) > MAX_LISTED:
        lines.append(f"  ... and {len(file.findings) - MAX_LISTED} more")
    return lines


def scan_for_rule(rule: str, files: list[FindingsFile]) -> Scan:
    """One scan holding every file's findings as evidence for the checklist rule `rule`."""
    if not is_v_number(rule):
        raise ChecklistError(f"--rule {rule!r} is not a V-number like V-222612")
    if not files:
        raise ChecklistError("no findings files to attach to the rule")
    total = sum(len(f.findings) for f in files)
    details = "\n".join(line for f in files for line in _summary(f))
    return Scan(
        source=" + ".join(dict.fromkeys(f.source for f in files)),
        tool=", ".join(dict.fromkeys(f.tool for f in files)),
        end_time="",
        stig_id="",
        version="",
        release_info="",
        hosts=(),
        # "fail" is imported as open; "no_findings" is counted and leaves the status alone.
        results=[RuleResult("", rule, "fail" if total else "no_findings", details)],
    )
