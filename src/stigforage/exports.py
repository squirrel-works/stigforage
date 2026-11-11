"""Exports (`export`): one row per rule, per STIG, per checklist, and the formats built on it.

Policy is ADR 0005. Every export starts from `finding_rows`, which flattens the input checklists
and, given DISA's CCI list, maps each rule's CCIs to NIST SP 800-53 Revision 5. Without a CCI
list the Revision 5 columns stay empty and the crosswalk summary says why.

Unit 2 writes CSV (decision 5): UTF-8 with a byte-order mark so Excel opens it correctly, CRLF
line endings, and any cell that Excel would run as a formula (starting with `=`, `+`, `-`, `@`,
tab or carriage return) neutralised with a leading apostrophe. Finding details often come from
scanners, so they are untrusted.

Pure functions only: no I/O, no logging.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Sequence
from dataclasses import dataclass, field

from stigforage.cci import CciList, crosswalk
from stigforage.model import Checklist, Status, Stig
from stigforage.results import release_id

__all__ = [
    "CSV_COLUMNS",
    "CrosswalkSummary",
    "FindingRow",
    "cat",
    "finding_rows",
    "release_label",
    "status_label",
    "to_csv",
]

STATUS_LABELS = {
    Status.OPEN: "Open",
    Status.NOT_A_FINDING: "Not a Finding",
    Status.NOT_APPLICABLE: "Not Applicable",
    Status.NOT_REVIEWED: "Not Reviewed",
}
_CAT = {"high": "I", "medium": "II", "low": "III"}
# OWASP's list for CSV injection: what Excel and LibreOffice treat as the start of a formula.
_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")

CSV_COLUMNS = (
    "Host", "STIG", "Release", "Vuln ID", "Rule ID", "STIG ID", "Severity", "CAT", "Status",
    "Rule Title", "Comments", "Finding Details", "CCIs", "NIST 800-53 Rev 5 Controls",
    "NIST 800-53 Rev 5 References", "Rev 5 Crosswalk Notes",
)  # fmt: skip


@dataclass(frozen=True)
class FindingRow:
    host: str
    stig_id: str
    release: str  # "V2R10", "V?R8" when only the release is known, else the release info
    group_id: str  # the V-number
    rule_id: str  # SV-...
    rule_version: str  # the STIG ID of the rule, e.g. RHEL-09-211010
    severity: str
    status: Status
    title: str
    comments: str
    finding_details: str
    ccis: tuple[str, ...]
    controls: tuple[str, ...]  # NIST form, e.g. AC-2(3); empty without a CCI list
    references: tuple[str, ...]  # DISA's text, e.g. AC-2 (3) (d)
    notes: tuple[str, ...]  # CCIs that did not map cleanly, and why


@dataclass
class CrosswalkSummary:
    """What the crosswalk did across every row, for the command's report."""

    applied: bool
    cci_list_version: str = ""
    cci_refs: int = 0  # distinct CCIs per rule, summed over rows
    mapped: int = 0
    unmapped: set[str] = field(default_factory=set)
    unknown: set[str] = field(default_factory=set)
    deprecated: set[str] = field(default_factory=set)


def cat(severity: str) -> str:
    """DISA's category for a severity: high -> I, medium -> II, low -> III; else ""."""
    return _CAT.get(severity, "")


def status_label(status: Status) -> str:
    return STATUS_LABELS[status]


def release_label(stig: Stig) -> str:
    rid = release_id(stig.version, stig.release_info)
    if rid is None:
        return stig.release_info.strip()
    return f"V{'?' if rid[0] is None else rid[0]}R{rid[1]}"


def finding_rows(
    checklists: Sequence[Checklist], cci_list: CciList | None
) -> tuple[list[FindingRow], CrosswalkSummary]:
    """Flatten checklists to one row per rule, per STIG, in input order."""
    rows: list[FindingRow] = []
    summary = CrosswalkSummary(cci_list is not None, cci_list.version if cci_list else "")
    for checklist in checklists:
        for stig in checklist.stigs:
            release = release_label(stig)
            for rule in stig.rules:
                controls: tuple[str, ...] = ()
                references: tuple[str, ...] = ()
                notes: list[str] = []
                if cci_list is not None:
                    result = crosswalk(rule.ccis, cci_list)
                    controls = tuple(result.controls)
                    references = tuple(r.reference for r in result.references)
                    notes += [f"{c}: no Rev 5 reference" for c in result.unmapped]
                    notes += [f"{c}: not in the CCI list" for c in result.unknown]
                    notes += [f"{c}: deprecated" for c in result.deprecated]
                    summary.cci_refs += len(set(rule.ccis))
                    summary.mapped += (
                        len(set(rule.ccis)) - len(result.unmapped) - len(result.unknown)
                    )
                    summary.unmapped.update(result.unmapped)
                    summary.unknown.update(result.unknown)
                    summary.deprecated.update(result.deprecated)
                rows.append(
                    FindingRow(
                        host=checklist.host_name,
                        stig_id=stig.stig_id,
                        release=release,
                        group_id=rule.group_id,
                        rule_id=rule.rule_id,
                        rule_version=rule.rule_version,
                        severity=rule.severity,
                        status=rule.status,
                        title=rule.rule_title,
                        comments=rule.comments or "",
                        finding_details=rule.finding_details or "",
                        ccis=tuple(dict.fromkeys(rule.ccis)),
                        controls=controls,
                        references=references,
                        notes=tuple(notes),
                    )
                )
    return rows, summary


def _cell(value: str) -> str:
    """Neutralise a cell Excel would otherwise evaluate as a formula."""
    return f"'{value}" if value.startswith(_FORMULA_STARTS) else value


def to_csv(rows: Sequence[FindingRow]) -> str:
    """CSV text in the column order of CSV_COLUMNS, with a leading byte-order mark."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        cells = (
            row.host, row.stig_id, row.release, row.group_id, row.rule_id, row.rule_version,
            row.severity, cat(row.severity), status_label(row.status), row.title, row.comments,
            row.finding_details, "; ".join(row.ccis), "; ".join(row.controls),
            "; ".join(row.references), "; ".join(row.notes),
        )  # fmt: skip
        writer.writerow([_cell(c) for c in cells])
    return "﻿" + buffer.getvalue()
