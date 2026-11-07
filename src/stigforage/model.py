"""Typed in-memory model mirroring the DISA STIG Viewer 3 CKLB checklist format.

Design notes:
- Only fields that program logic needs are typed. Everything else is kept verbatim in `extra`
  so a read/write round trip never drops data, including tool-specific keys such as
  Evaluate-STIG's `evaluate-stig` / `cklb_version` blocks, and fields DISA adds later.
- Pure data and pure functions only: no I/O and no logging here.
"""

from __future__ import annotations

import enum
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "SEVERITIES",
    "Checklist",
    "ChecklistError",
    "Issue",
    "Rule",
    "Status",
    "Stig",
    "validate",
]

SEVERITIES = frozenset({"high", "medium", "low"})
_CCI_RE = re.compile(r"^CCI-\d{6}$")


class ChecklistError(ValueError):
    """Malformed checklist data. The message always starts with a JSON-path style locator."""


class Status(enum.StrEnum):
    """Review status values as written by STIG Viewer 3."""

    NOT_REVIEWED = "not_reviewed"
    NOT_APPLICABLE = "not_applicable"
    OPEN = "open"
    NOT_A_FINDING = "not_a_finding"


@dataclass
class Rule:
    """One STIG rule plus its review state."""

    group_id: str
    rule_id: str
    rule_version: str
    severity: str
    status: Status
    uuid: str = ""
    rule_id_src: str | None = None
    rule_title: str = ""
    comments: str | None = None
    finding_details: str | None = None
    overrides: dict[str, Any] = field(default_factory=dict)
    ccis: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Stig:
    """One STIG (benchmark) inside a checklist."""

    stig_name: str
    display_name: str
    stig_id: str
    release_info: str
    rules: list[Rule]
    # Absent in 9 of 34 STIGs in the public fixtures, and a string ("2") far more often than an
    # int. The original type is kept so round trips are lossless.
    version: int | str | None = None
    uuid: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def status_counts(self) -> Counter[Status]:
        return Counter(rule.status for rule in self.rules)

    def severity_counts(self) -> Counter[str]:
        return Counter(rule.severity for rule in self.rules)


@dataclass
class Checklist:
    """A whole CKLB checklist: target asset metadata plus one or more STIGs."""

    title: str
    id: str
    target_data: dict[str, Any]
    stigs: list[Stig]
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def host_name(self) -> str:
        value = self.target_data.get("host_name")
        return value if isinstance(value, str) else ""


@dataclass(frozen=True)
class Issue:
    """A structural problem found by `validate`."""

    level: Literal["error", "warning"]
    path: str
    message: str


def validate(checklist: Checklist) -> list[Issue]:
    """Return structural issues. Parsing already guarantees types and status values.

    This checks semantic invariants the parser deliberately does not enforce, so that real-world
    files with quirks can still be loaded and inspected.
    """
    issues: list[Issue] = []
    if not checklist.stigs:
        issues.append(Issue("warning", "stigs", "checklist contains no STIGs"))
    for si, stig in enumerate(checklist.stigs):
        spath = f"stigs[{si}]"
        if not stig.rules:
            issues.append(Issue("warning", spath, f"STIG {stig.stig_id!r} contains no rules"))
        seen: dict[str, int] = {}
        for ri, rule in enumerate(stig.rules):
            rpath = f"{spath}.rules[{ri}]"
            if rule.severity not in SEVERITIES:
                issues.append(
                    Issue("error", rpath, f"severity {rule.severity!r} is not high/medium/low")
                )
            if rule.group_id in seen:
                # Warning, not error: the public fixtures (cloned-rule test data) contain
                # duplicates and STIG Manager's own parsers accept them. DISA's uniqueness
                # guarantee for real benchmarks is unverified.
                issues.append(
                    Issue(
                        "warning",
                        rpath,
                        f"duplicate group_id {rule.group_id!r} "
                        f"(first seen at rules[{seen[rule.group_id]}])",
                    )
                )
            else:
                seen[rule.group_id] = ri
            issues.extend(
                Issue("warning", rpath, f"malformed CCI identifier {cci!r}")
                for cci in rule.ccis
                if not _CCI_RE.match(cci)
            )
    return issues
