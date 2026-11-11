"""Apply scan results to a checklist (`import-results`).

Unit 1 reads XCCDF result files as written by SCC, Evaluate-STIG, OpenSCAP and STIG Manager: an
XCCDF `Benchmark` holding a `TestResult`, or an ARF `asset-report-collection` wrapping either.
Policy is ADR 0003:
- Results map pass -> not_a_finding, fail -> open, notapplicable -> not_applicable. Every other
  result is not imported and is counted.
- A scan's review is its status and finding details; comments and overrides are never touched.
  The checklist wins a conflict unless `prefer="results"`.
- A scan pairs with the checklist STIG of the same id (benchmark prefix dropped) and must be the
  same release, compared as (version, release) numbers. Rules pair through `diff.match_rules`.
- A scan of another host is refused unless `allow_host_mismatch`.

Trust boundary: result files are untrusted. XML goes through `xmlsafe`, and malformed content
raises ChecklistError with a locator.
"""

from __future__ import annotations

import copy
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from stigforage.diff import match_rules
from stigforage.fsio import read_limited
from stigforage.model import (
    Checklist,
    ChecklistError,
    Rule,
    Status,
    Stig,
    pretty_group_id,
    pretty_rule_id,
)
from stigforage.xmlsafe import local_name, parse_xml

__all__ = [
    "ResultsImport",
    "RuleResult",
    "Scan",
    "ScanConflict",
    "ScanImport",
    "import_results",
    "load_xccdf_results",
    "loads_xccdf_results",
    "release_id",
]

Prefer = Literal["checklist", "results"]

_BENCHMARK_PREFIX = "xccdf_mil.disa.stig_benchmark_"
_RULE_PREFIX = "xccdf_mil.disa.stig_rule_"
_STATUS = {
    "pass": Status.NOT_A_FINDING,
    "fail": Status.OPEN,
    "notapplicable": Status.NOT_APPLICABLE,
}
_HOST_FACTS = frozenset({"host_name", "hostname", "fqdn"})


@dataclass(frozen=True)
class RuleResult:
    rule_id_src: str  # benchmark prefix dropped, e.g. "SV-251545r879827_rule"
    group_id: str  # "V-251545", or "" when the file has no Group for the rule
    result: str  # the XCCDF result value as written
    details: str  # the scanner's messages and detail text


@dataclass
class Scan:
    source: str
    tool: str  # the TestResult's test-system, e.g. "cpe:/a:niwc:scc:5.8"
    end_time: str
    stig_id: str  # benchmark prefix dropped; "" when the format names none (HDF)
    version: str
    release_info: str
    hosts: tuple[str, ...]  # target name and host-name facts, as written
    results: list[RuleResult]


@dataclass(frozen=True)
class ScanConflict:
    group_id: str
    rule_id: str
    checklist_status: Status
    scan_status: Status
    reason: Literal["status", "finding_details"]


@dataclass
class ScanImport:
    source: str
    tool: str
    end_time: str
    stig_id: str
    applied: int = 0
    unchanged: int = 0
    matched: int = 0
    matched_by_group_id: int = 0
    conflicts: list[ScanConflict] = field(default_factory=list)
    not_imported: Counter[str] = field(default_factory=Counter)  # by XCCDF result value
    unmatched: list[RuleResult] = field(default_factory=list)  # no rule in the checklist
    ambiguous: list[str] = field(default_factory=list)


@dataclass
class ResultsImport:
    checklist: Checklist
    prefer: Prefer
    scans: list[ScanImport] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# --- release identity -----------------------------------------------------------------------

_VR_RE = re.compile(r"^V(\d+)R(\d+)$", re.IGNORECASE)
_DOTTED_RE = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)?$")
_RELEASE_RE = re.compile(r"\bRelease:\s*(\d+)")


ReleaseId = tuple[int | None, int]


def release_id(version: object, release_info: str) -> ReleaseId | None:
    """(version, release) from the forms seen in real files (ADR 0003), or None.

    `V2R5` (STIG Manager, Evaluate-STIG), `002.010` (DISA SCAP), `6.3.3` (SCC enhanced content),
    or "Release: 10" in the release info with a plain `2` as the version. Schema-valid CKLB has
    no STIG-level version at all, so the version part is None when only the release is known.
    """
    text = "" if version is None else str(version).strip()
    if match := _VR_RE.match(text):
        return int(match[1]), int(match[2])
    if match := _DOTTED_RE.match(text):
        return int(match[1]), int(match[2])
    if match := _RELEASE_RE.search(release_info):
        return (int(text) if text.isdigit() else None), int(match[1])
    return None


def _same_release(a: ReleaseId, b: ReleaseId) -> bool:
    """Releases must agree; versions only where both sides know theirs."""
    return a[1] == b[1] and (a[0] is None or b[0] is None or a[0] == b[0])


def _show_release(rid: ReleaseId | None) -> str:
    if rid is None:
        return "unknown release"
    return f"V{'?' if rid[0] is None else rid[0]}R{rid[1]}"


# --- parsing --------------------------------------------------------------------------------


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in element if local_name(c.tag) == name]


def _text(element: ET.Element | None) -> str:
    return (element.text or "").strip() if element is not None else ""


def _group_map(benchmarks: list[ET.Element]) -> dict[str, str]:
    """Rule id (prefix dropped) -> V-number, from every Group in the file's benchmarks."""
    groups: dict[str, str] = {}
    for benchmark in benchmarks:
        for group in (e for e in benchmark.iter() if local_name(e.tag) == "Group"):
            for rule in _children(group, "Rule"):
                if rule.get("id") and group.get("id"):
                    groups[rule.get("id", "").removeprefix(_RULE_PREFIX)] = pretty_group_id(
                        group.get("id", "")
                    )
    return groups


def _details(rule_result: ET.Element) -> str:
    # SCC and Evaluate-STIG write <message>; STIG Manager exports write check-content/<detail>.
    # The rest of check-content is the check text (SCC copies it there), not a finding.
    parts = [_text(m) for m in _children(rule_result, "message")]
    parts += [_text(d) for d in rule_result.iter() if local_name(d.tag) == "detail"]
    return "\n".join(p for p in parts if p)


def _benchmark_for(named: str, benchmarks: list[ET.Element]) -> ET.Element | None:
    """The Benchmark a TestResult names, or the file's only Benchmark (ARF may hold several)."""
    for benchmark in benchmarks:
        if named and benchmark.get("id") == named:
            return benchmark
    return benchmarks[0] if len(benchmarks) == 1 else None


def _scan(
    test_result: ET.Element, benchmarks: list[ET.Element], groups: dict[str, str], where: str
) -> Scan:
    named = next((c.get("id", "") for c in _children(test_result, "benchmark")), "")
    benchmark = _benchmark_for(named, benchmarks)
    stig_id = (benchmark.get("id", "") if benchmark is not None else "") or named
    if not stig_id:
        raise ChecklistError(f"{where}: cannot tell which benchmark this TestResult is for")
    version = release_info = ""
    if benchmark is not None:
        version = _text(next(iter(_children(benchmark, "version")), None))
        for plain in _children(benchmark, "plain-text"):
            if plain.get("id") == "release-info":
                release_info = _text(plain)
    hosts = [_text(t) for t in _children(test_result, "target")]
    hosts += [
        _text(f)
        for f in test_result.iter()
        if local_name(f.tag) == "fact" and f.get("name", "").rsplit(":", 1)[-1] in _HOST_FACTS
    ]
    results: list[RuleResult] = []
    for i, rule_result in enumerate(
        e for e in test_result.iter() if local_name(e.tag) == "rule-result"
    ):
        idref = rule_result.get("idref", "")
        if not idref:
            raise ChecklistError(f"{where}.rule-result[{i}]: missing idref")
        value = _text(next(iter(_children(rule_result, "result")), None))
        if not value:
            raise ChecklistError(f"{where}.rule-result[{i}] ({idref}): missing result")
        rule_id_src = idref.removeprefix(_RULE_PREFIX)
        results.append(
            RuleResult(rule_id_src, groups.get(rule_id_src, ""), value, _details(rule_result))
        )
    if not results:
        raise ChecklistError(f"{where}: TestResult holds no rule-result elements")
    return Scan(
        source=where,
        tool=test_result.get("test-system", ""),
        end_time=test_result.get("end-time", ""),
        stig_id=stig_id.removeprefix(_BENCHMARK_PREFIX),
        version=version,
        release_info=release_info,
        hosts=tuple(h for h in hosts if h),
        results=results,
    )


def loads_xccdf_results(data: bytes, *, source: str = "XCCDF results") -> list[Scan]:
    """Parse an XCCDF results file or ARF collection into one Scan per TestResult."""
    root = parse_xml(data, source=source)
    kind = local_name(root.tag)
    if kind not in ("Benchmark", "asset-report-collection"):
        raise ChecklistError(
            f"{source}: root element {kind!r} is neither an XCCDF Benchmark nor an ARF "
            "asset-report-collection"
        )
    benchmarks = [e for e in root.iter() if local_name(e.tag) == "Benchmark"]
    test_results = [e for e in root.iter() if local_name(e.tag) == "TestResult"]
    if not test_results:
        raise ChecklistError(
            f"{source}: no TestResult element; this is a benchmark, not scan results"
        )
    groups = _group_map(benchmarks)
    return [
        _scan(tr, benchmarks, groups, source if len(test_results) == 1 else f"{source}[{i}]")
        for i, tr in enumerate(test_results)
    ]


def load_xccdf_results(path: Path) -> list[Scan]:
    """Read an XCCDF results or ARF `.xml` file. Raises ChecklistError, OSError."""
    return loads_xccdf_results(read_limited(path), source=str(path))


# --- applying -------------------------------------------------------------------------------


def _short_host(name: str) -> str:
    return name.strip().split(".", 1)[0].casefold()


def _candidates(scan: Scan, output: Checklist) -> list[Stig]:
    """Checklist STIGs a scan could be for, refusing when there is not exactly one.

    XCCDF results name their benchmark. HDF does not (profile names are free text), so a scan
    with no STIG id pairs with the STIG holding its V-numbers (ADR 0003, unit 2).
    """
    if scan.stig_id:
        candidates = [
            s for s in output.stigs if s.stig_id.removeprefix(_BENCHMARK_PREFIX) == scan.stig_id
        ]
        if len(candidates) != 1:
            found = "no STIG" if not candidates else f"{len(candidates)} STIGs"
            raise ChecklistError(
                f"{scan.source}: scan is for {scan.stig_id!r} but the checklist has {found} "
                "with that id"
            )
        return candidates
    v_numbers = {r.group_id for r in scan.results if r.group_id}
    candidates = [s for s in output.stigs if v_numbers & {r.group_id for r in s.rules}]
    if not candidates:
        raise ChecklistError(
            f"{scan.source}: none of the scan's {len(v_numbers)} V-numbers is in the checklist"
        )
    if len(candidates) > 1:
        raise ChecklistError(
            f"{scan.source}: the scan's V-numbers are spread over {len(candidates)} checklist "
            f"STIGs ({', '.join(s.stig_id for s in candidates)})"
        )
    return candidates


def _pair(scans: list[Scan], output: Checklist) -> list[Stig]:
    """The checklist STIG for each scan, refusing anything ambiguous."""
    paired: list[Stig] = []
    for scan in scans:
        [stig] = _candidates(scan, output)
        if any(stig is p for p in paired):
            raise ChecklistError(
                f"{scan.source}: another results file is also for {stig.stig_id!r}; import "
                "one scan per STIG at a time"
            )
        paired.append(stig)
    return paired


def _check_release(scan: Scan, stig: Stig, warnings: list[str]) -> bool:
    """Refuse a different release (ADR 0003 decision 6). Returns whether it could be compared."""
    scan_rid = release_id(scan.version, scan.release_info)
    stig_rid = release_id(stig.version, stig.release_info)
    if scan_rid and stig_rid and not _same_release(scan_rid, stig_rid):
        raise ChecklistError(
            f"{scan.source}: scan is {stig.stig_id.removeprefix(_BENCHMARK_PREFIX)} "
            f"{_show_release(scan_rid)} but the checklist STIG is {_show_release(stig_rid)}; "
            "results only apply to the release they scanned"
        )
    if not (scan_rid and stig_rid):
        warnings.append(
            f"{scan.source}: release could not be compared (scan {_show_release(scan_rid)}, "
            f"checklist {_show_release(stig_rid)})"
        )
        return False
    return True


def _check_host(
    scan: Scan, checklist: Checklist, allow_host_mismatch: bool, warnings: list[str]
) -> None:
    """Refuse a scan of another host unless allowed (ADR 0003 decision 7)."""
    host = checklist.host_name.strip()
    if not host:
        return
    if not scan.hosts:
        warnings.append(f"{scan.source}: scan names no host, so the host was not checked")
        return
    if _short_host(host) not in {_short_host(h) for h in scan.hosts}:
        message = (
            f"{scan.source}: scan is of {', '.join(sorted(set(scan.hosts)))} but the checklist "
            f"is for {host!r}"
        )
        if not allow_host_mismatch:
            raise ChecklistError(f"{message} (use --allow-host-mismatch if this is intended)")
        warnings.append(f"{message}; imported anyway (--allow-host-mismatch)")


def _apply(scan: Scan, stig: Stig, prefer: Prefer) -> ScanImport:
    report = ScanImport(scan.source, scan.tool, scan.end_time, stig.stig_id)
    # match_rules pairs Rule objects, so each result gets a stand-in Rule carrying its ids.
    stand_ins = [
        Rule(
            group_id=rr.group_id,
            rule_id=pretty_rule_id(rr.rule_id_src),
            rule_version="",
            severity="unknown",
            status=Status.NOT_REVIEWED,
            rule_id_src=rr.rule_id_src,
        )
        for rr in scan.results
    ]
    by_stand_in = {id(s): rr for s, rr in zip(stand_ins, scan.results, strict=True)}
    matching = match_rules(stand_ins, stig.rules)
    report.matched = len(matching.pairs)
    report.ambiguous = matching.ambiguous
    report.unmatched = [by_stand_in[id(r)] for r in matching.old_only]
    header = (
        f"[stigforage import-results] {scan.tool or 'unknown tool'}, scan ended "
        f"{scan.end_time or 'at an unknown time'}"
    )
    for stand_in, rule, matched_by in matching.pairs:
        result = by_stand_in[id(stand_in)]
        if matched_by == "group_id":
            report.matched_by_group_id += 1
        status = _STATUS.get(result.result)
        if status is None:
            report.not_imported[result.result] += 1
            continue
        details = f"{header}: {result.result}" + (f"\n{result.details}" if result.details else "")
        if rule.status == Status.NOT_REVIEWED and not rule.finding_details:
            rule.status, rule.finding_details = status, details
            report.applied += 1
        elif rule.status == status:
            report.unchanged += 1
        else:
            reason: Literal["status", "finding_details"] = (
                "status" if rule.status != Status.NOT_REVIEWED else "finding_details"
            )
            report.conflicts.append(
                ScanConflict(rule.group_id, rule.rule_id, rule.status, status, reason)
            )
            if prefer == "results":
                rule.status, rule.finding_details = status, details
    return report


def import_results(
    checklist: Checklist,
    scans: list[Scan],
    *,
    prefer: Prefer = "checklist",
    allow_host_mismatch: bool = False,
) -> ResultsImport:
    """Return a copy of `checklist` with the scans' results applied, plus a report.

    Raises ChecklistError, before applying anything, when a scan pairs with no STIG or the same
    STIG as another scan, is for a different release, or (without `allow_host_mismatch`) is of
    another host.
    """
    output = copy.deepcopy(checklist)
    result = ResultsImport(output, prefer)
    stigs = _pair(scans, output)
    compared: list[bool] = []
    for scan, stig in zip(scans, stigs, strict=True):
        compared.append(_check_release(scan, stig, result.warnings))
        _check_host(scan, output, allow_host_mismatch, result.warnings)
    result.scans = [_apply(scan, stig, prefer) for scan, stig in zip(scans, stigs, strict=True)]
    for report, was_compared in zip(result.scans, compared, strict=True):
        # Unknown release, but rule revisions disagree: the best remaining sign of drift.
        # (A known release is already checked; SCAP and manual revisions differ even then.)
        if not was_compared and report.matched_by_group_id:
            result.warnings.append(
                f"{report.source}: {report.matched_by_group_id} of {report.matched} matched "
                "rules have a different rule revision than the checklist; the scan may be for "
                "another release"
            )
    return result
