"""Exports (`export`): one row per rule, per STIG, per checklist, and the formats built on it.

Policy is ADR 0005. Every export starts from `finding_rows`, which flattens the input checklists
and, given DISA's CCI list, maps each rule's CCIs to NIST SP 800-53 Revision 5. Without a CCI
list the Revision 5 columns stay empty and the crosswalk summary says why.

Unit 2 writes CSV (decision 5): UTF-8 with a byte-order mark so Excel opens it correctly, CRLF
line endings, and any cell that Excel would run as a formula (starting with `=`, `+`, `-`, `@`,
tab or carriage return) neutralised with a leading apostrophe. Finding details often come from
scanners, so they are untrusted.

Unit 3 fills the user's own eMASS POA&M template (decisions 6 and 7, as revised): one row per
open rule across every checklist, in the columns the template's headers name.

Pure functions only: no I/O, no logging.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date

from stigforage.cci import CciList, crosswalk
from stigforage.model import Checklist, ChecklistError, Status, Stig
from stigforage.results import release_id
from stigforage.xlsx import Cell, Template, fill_template, normalize_header, read_template

__all__ = [
    "BOM",
    "CSV_COLUMNS",
    "NO_HOST",
    "POAM_FIELDS",
    "POAM_SHEET",
    "POAM_STATUSES",
    "CrosswalkSummary",
    "FindingRow",
    "PoamOptions",
    "PoamSummary",
    "cat",
    "finding_rows",
    "poam_columns",
    "poam_items",
    "poam_template",
    "release_label",
    "status_label",
    "to_csv",
    "to_poam_xlsx",
]

STATUS_LABELS = {
    Status.OPEN: "Open",
    Status.NOT_A_FINDING: "Not a Finding",
    Status.NOT_APPLICABLE: "Not Applicable",
    Status.NOT_REVIEWED: "Not Reviewed",
}
_CAT = {"high": "I", "medium": "II", "low": "III"}
BOM = chr(0xFEFF)  # byte-order mark: Excel reads a CSV as UTF-8 only when it starts with one
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
    release_info: str  # as written, e.g. "Release: 10 Benchmark Date: 30 Sep 2026"
    group_id: str  # the V-number
    rule_id: str  # SV-...
    rule_version: str  # the STIG ID of the rule, e.g. RHEL-09-211010
    severity: str
    status: Status
    title: str
    comments: str
    finding_details: str
    discussion: str  # the rule's vulnerability discussion (POA&M description)
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
                        release_info=stig.release_info.strip(),
                        group_id=rule.group_id,
                        rule_id=rule.rule_id,
                        rule_version=rule.rule_version,
                        severity=rule.severity,
                        status=rule.status,
                        title=rule.rule_title,
                        comments=rule.comments or "",
                        finding_details=rule.finding_details or "",
                        discussion=str(rule.extra.get("discussion") or ""),
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
    return BOM + buffer.getvalue()


# --- POA&M (unit 3; ADR 0005 decisions 6 and 7, as revised) ---------------------------------

POAM_SHEET = "POA&M"
POAM_STATUSES = ("Ongoing", "Risk Accepted")
# The eMASS template's columns this export fills, headed as the current Navy, Army and Marine
# Corps templates head them. Columns are found by header, compared with whitespace and case
# normalised, so each branch's layout works and a stray space in a header does not matter.
POAM_FIELDS = (
    "Control Vulnerability Description",
    "Controls / APs",
    "Security Checks",
    "POA&M Status",
    "POA&M Scheduled Completion Date",
    "Milestone Description",
    "Milestone Status",
    "Milestone Scheduled Completion Date",
    "Identification Source Details",
    "Office/Org",
    "Comments",
    "Raw Severity",
    "Devices Affected",
    "Severity",
)
_HEADER_MARKER = "Control Vulnerability Description"  # identifies the template's header row
# Fields the templates' instructions require before eMASS imports an item, by status. Resources
# Required and Identification Source (a value from eMASS's glossary) are always left to the
# assessor, so they are always reported.
_REQUIRED = {
    "Ongoing": (
        "Control Vulnerability Description",
        "POA&M Scheduled Completion Date",
        "Office/Org",
        "Resources Required",
        "Identification Source",
        "Milestone Scheduled Completion Date",
    ),
    "Risk Accepted": (
        "Control Vulnerability Description",
        "Office/Org",
        "Resources Required",
        "Comments",
        "Identification Source",
    ),
}
_MILESTONE = "Resolve this finding."
_MILESTONE_STATUS = "Open"
_RISK = {"high": "High", "medium": "Moderate", "low": "Low"}
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}  # most severe first; anything else last
NO_HOST = "(no host name)"


@dataclass(frozen=True)
class PoamOptions:
    """The assessor's fields, the same for every item."""

    office: str = ""
    completion_date: date | None = None
    status: str = "Ongoing"

    def __post_init__(self) -> None:
        if self.status not in POAM_STATUSES:
            raise ValueError(f"POA&M status {self.status!r} is not one of {POAM_STATUSES}")
        if self.status == "Risk Accepted" and self.completion_date is not None:
            raise ValueError("a Risk Accepted item takes no completion date: it has no milestone")


@dataclass(frozen=True)
class PoamSummary:
    items: int  # POA&M rows
    open_rules: int  # open rules across all checklists, before grouping
    not_reviewed: int  # rules left out because nobody has reviewed them
    # (field, items) for each field eMASS requires that this export leaves empty
    empty_required: tuple[tuple[str, int], ...] = ()


def _v_number_key(group_id: str) -> tuple[int, str]:
    digits = group_id.removeprefix("V-")
    return (int(digits), "") if digits.isdigit() else (0, group_id)


def _join(values: Sequence[str], separator: str = "\n") -> str:
    return separator.join(dict.fromkeys(v for v in values if v))


def _comments(members: Sequence[FindingRow]) -> str:
    """The CCIs, then any crosswalk notes: an empty Controls / APs cell then says why."""
    ccis = _join([c for m in members for c in m.ccis])
    notes = _join([n for m in members for n in m.notes])
    return f"{ccis}\n\n{notes}" if ccis and notes else ccis or notes


def poam_items(
    rows: Sequence[FindingRow], options: PoamOptions
) -> tuple[list[dict[str, Cell]], PoamSummary]:
    """One POA&M item per open rule, grouped by STIG and V-number across every checklist.

    Each item maps template headers (`POAM_FIELDS`) to values; a field left empty is absent.
    Grouping by V-number keeps one item per vulnerability when hosts are on different revisions
    of a rule; every rule id and host is listed. CAT I items come first.
    """
    groups: dict[tuple[str, str], list[FindingRow]] = {}
    for row in rows:
        if row.status == Status.OPEN:
            groups.setdefault((row.stig_id, row.group_id), []).append(row)
    ranked: list[tuple[tuple[int, str, tuple[int, str]], dict[str, Cell]]] = []
    for (stig_id, group_id), members in groups.items():
        first = members[0]
        severity = min((m.severity for m in members), key=lambda s: _SEVERITY_RANK.get(s, 3))
        risk = _RISK.get(severity, "")
        # One block per distinct STIG release, blank line between: hosts may be on different ones.
        sources = "\n\n".join(
            dict.fromkeys(f"{m.stig_id}\n{m.release}\n{m.release_info}".strip() for m in members)
        )
        values: dict[str, Cell] = {
            "Control Vulnerability Description": (
                f"Title:\n{first.title}\n\nDescription:\n{first.discussion}"
            ),
            # The templates' instructions: several controls or checks are separated by semicolons.
            "Controls / APs": _join([c for m in members for c in m.controls], ";"),
            "Security Checks": _join([m.rule_id or m.group_id for m in members], ";"),
            "POA&M Status": options.status,
            "Identification Source Details": sources,
            "Office/Org": options.office,
            "Comments": _comments(members),
            "Raw Severity": risk,
            "Devices Affected": _join([m.host or NO_HOST for m in members]),
            "Severity": risk,
        }
        if options.status == "Ongoing":  # eMASS refuses milestones on Risk Accepted items
            values["Milestone Description"] = _MILESTONE
            values["Milestone Status"] = _MILESTONE_STATUS
            if options.completion_date is not None:
                values["POA&M Scheduled Completion Date"] = options.completion_date
                values["Milestone Scheduled Completion Date"] = options.completion_date
        item = {k: v for k, v in values.items() if v != ""}
        ranked.append(((_SEVERITY_RANK.get(severity, 3), stig_id, _v_number_key(group_id)), item))
    ranked.sort(key=lambda pair: pair[0])
    items = [item for _, item in ranked]
    empty = ((f, sum(1 for i in items if f not in i)) for f in _REQUIRED[options.status])
    summary = PoamSummary(
        items=len(items),
        open_rules=sum(len(m) for m in groups.values()),
        not_reviewed=sum(1 for r in rows if r.status == Status.NOT_REVIEWED),
        empty_required=tuple((f, n) for f, n in empty if n),
    )
    return items, summary


def poam_columns(template: Template) -> dict[str, int]:
    """The template's column for each of `POAM_FIELDS`. Raises ChecklistError when one is
    missing or appears twice: the template is then not one this export can fill."""
    found = {f: template.headers.get(normalize_header(f), []) for f in POAM_FIELDS}
    missing = [f for f, columns in found.items() if not columns]
    twice = [f for f, columns in found.items() if len(columns) > 1]
    if missing or twice:
        problems = ([f"no column headed {', '.join(map(repr, missing))}"] if missing else []) + (
            [f"more than one column headed {', '.join(map(repr, twice))}"] if twice else []
        )
        raise ChecklistError(
            f"{template.source}: not an eMASS POA&M template this version can fill: "
            + "; ".join(problems)
        )
    return {f: columns[0] for f, columns in found.items()}


def poam_template(data: bytes, *, source: str = "template") -> Template:
    """Read an eMASS POA&M template (`.xlsx` bytes) and check it can be filled.

    Raises ChecklistError for anything else, or for a template that already holds items."""
    template = read_template(data, sheet=POAM_SHEET, marker=_HEADER_MARKER, source=source)
    poam_columns(template)
    return template


def to_poam_xlsx(
    rows: Sequence[FindingRow], options: PoamOptions, template: Template
) -> tuple[bytes, PoamSummary]:
    """`template` filled with the POA&M items, one row each below its header."""
    columns = poam_columns(template)
    items, summary = poam_items(rows, options)
    cells = [{columns[f]: value for f, value in item.items()} for item in items]
    return fill_template(template, cells), summary
