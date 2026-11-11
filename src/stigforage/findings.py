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

Trust boundary: findings files are untrusted; malformed content raises ChecklistError with a
locator.
"""

from __future__ import annotations

import json
import re
from collections import Counter
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
    "load_sarif",
    "loads_sarif",
    "scan_for_rule",
]

# Findings listed per file in the finding details; the counts above the list stay complete.
# A dependency scan can report hundreds of CVEs, and the details are meant to be read.
MAX_LISTED = 50
_LEVELS = frozenset({"error", "warning", "note", "none"})
_V_NUMBER_RE = re.compile(r"^V-\d+$")


@dataclass(frozen=True)
class Finding:
    rule_id: str  # the tool's rule, e.g. CVE-2019-1549 or FF1014
    level: str  # error, warning, note or none
    message: str  # collapsed to one line
    location: str  # "path:line", or ""


@dataclass
class FindingsFile:
    source: str
    tool: str
    findings: list[Finding]
    not_counted: Counter[str] = field(default_factory=Counter)  # by reason


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


def loads_sarif(text: str, *, source: str = "SARIF") -> list[FindingsFile]:
    """Parse SARIF 2.1.0 JSON into one FindingsFile per run (per tool)."""
    try:
        doc = _dict(json.loads(text, parse_constant=_reject_constant), source)
    except json.JSONDecodeError as exc:
        raise ChecklistError(
            f"{source}: invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    if doc.get("version") != "2.1.0":
        _fail(f"{source}.version", f"expected SARIF 2.1.0, got {doc.get('version')!r}")
    runs = _list(doc.get("runs"), f"{source}.runs")
    if not runs:
        _fail(f"{source}.runs", "no runs")
    return [_run(_dict(r, f"{source}.runs[{i}]"), f"{source}.runs[{i}]", source)
            for i, r in enumerate(runs)]  # fmt: skip


def load_sarif(path: Path) -> list[FindingsFile]:
    """Read a SARIF file. Raises ChecklistError, OSError."""
    data = read_limited(path)
    try:
        return loads_sarif(data.decode("utf-8-sig"), source=str(path))
    except UnicodeDecodeError as exc:
        raise ChecklistError(f"{path}: not valid UTF-8: {exc.reason}") from exc


def _summary(file: FindingsFile) -> list[str]:
    levels = Counter(f.level for f in file.findings)
    by_level = ", ".join(
        f"{k} {levels[k]}" for k in ("error", "warning", "note", "none") if k in levels
    )
    head = f"{file.tool} ({file.source}): {len(file.findings)} finding(s)"
    head += f" ({by_level})" if by_level else ""
    if file.not_counted:
        head += "; not counted: " + ", ".join(
            f"{k} {v}" for k, v in sorted(file.not_counted.items())
        )
    lines = [head]
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
