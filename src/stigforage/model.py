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
import uuid
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "NULL_WHEN_EMPTY",
    "SEVERITIES",
    "Checklist",
    "ChecklistError",
    "ImportResult",
    "Issue",
    "Rule",
    "Status",
    "Stig",
    "default_target_data",
    "make_checklist",
    "make_rule",
    "make_stig",
    "new_uuid",
    "parse_version",
    "validate",
]

SEVERITIES = frozenset({"unknown", "low", "medium", "high"})  # per the DISA CKLB schema
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
    # The DISA CKLB schema has no STIG-level `version`, but many tools write one. We keep it in
    # memory either way and only write it back when the source file had it, so checklists we
    # generate stay schema-valid.
    write_version: bool = True
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


@dataclass
class ImportResult:
    """A parsed checklist plus non-fatal notes about data that could not be carried over."""

    checklist: Checklist
    warnings: list[str] = field(default_factory=list)


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
                    Issue(
                        "error", rpath, f"severity {rule.severity!r} is not unknown/low/medium/high"
                    )
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


# --- builders shared by the CKL and XCCDF importers -------------------------------------------
#
# Generated checklists follow the DISA "SV3_CKLB_1_0_JSON_SCHEMA" (2024-01-10): additional
# properties are not allowed, most text fields must be strings (never null), and only target_key,
# stig_ref, reference_identifier, check_content and check_content_ref may be null.
# Still inferred rather than documented: `active`/`mode`/`has_path` values and
# check_content_ref.name "M" (copied from public fixtures), and the exact rule_id prettifying.

IdFactory = Callable[[], str]

CKLB_VERSION = "1.0"
_GROUP_PREFIX = "xccdf_mil.disa.stig_group_"
_RULE_PREFIXES = ("xccdf_mil.disa.stig_rule_", "rule_")


def new_uuid() -> str:
    return str(uuid.uuid4())


def pretty_group_id(group_id_src: str) -> str:
    """Display form of a Group id: drops the SCAP `xccdf_mil.disa.stig_group_` prefix."""
    return group_id_src.removeprefix(_GROUP_PREFIX)


def pretty_rule_id(rule_id_src: str) -> str:
    """Display form of a Rule id: drops SCAP prefixes and the trailing `_rule`.

    The suffix removal follows the public CKLB fixtures (`SV-257777r925318_rule` is shown as
    `SV-257777r925318`); the schema only says "removes text like ... 'rule_'".
    """
    for prefix in _RULE_PREFIXES:
        if rule_id_src.startswith(prefix):
            rule_id_src = rule_id_src[len(prefix) :]
            break
    return rule_id_src.removesuffix("_rule")


def parse_version(raw: str) -> int | str | None:
    """Digits become int; anything else stays a string; empty is None."""
    raw = raw.strip()
    if not raw:
        return None
    return int(raw) if raw.isdigit() else raw


def default_target_data() -> dict[str, Any]:
    return {
        "target_type": "Computing",
        "host_name": "",
        "ip_address": "",
        "mac_address": "",
        "fqdn": "",
        "comments": "",
        "role": "None",
        "is_web_database": False,
        "technology_area": "",
        "web_db_site": "",
        "web_db_instance": "",
    }


# Fields the schema allows to be null; every other text field is written as "" when empty.
NULL_WHEN_EMPTY = frozenset({"stig_ref", "target_key", "reference_identifier"})
_STRING_FIELDS = (
    "fix_text",
    "false_positives",
    "false_negatives",
    "discussion",
    "check_content",
    "documentable",
    "mitigations",
    "potential_impacts",
    "third_party_tools",
    "mitigation_control",
    "responsibility",
    "security_override_guidance",
    "ia_controls",
)
_RULE_FIELD_NAMES = frozenset(
    {
        *_STRING_FIELDS,
        *NULL_WHEN_EMPTY,
        "weight",
        "classification",
        "group_title",
        "group_description",
        "group_id_src",
        "check_content_ref",
        "legacy_ids",
    }
)


def make_rule(
    *,
    new_id: IdFactory,
    stig_uuid: str,
    group_id: str,
    rule_id_src: str,
    rule_version: str,
    severity: str,
    rule_title: str = "",
    status: Status = Status.NOT_REVIEWED,
    comments: str = "",
    finding_details: str = "",
    ccis: Iterable[str] = (),
    **fields: Any,
) -> Rule:
    """Build a schema-valid Rule. Unknown keyword arguments raise (typo guard)."""
    unknown = set(fields) - _RULE_FIELD_NAMES
    if unknown:
        raise TypeError(f"unknown rule field(s): {sorted(unknown)}")
    group_title = fields.get("group_title", "")
    extra: dict[str, Any] = {
        "stig_uuid": stig_uuid,
        "weight": fields.get("weight", "10.0"),
        "classification": fields.get("classification", "NONE"),
        "group_title": group_title,
        "check_content_ref": fields.get("check_content_ref", {"href": "", "name": "M"}),
        "legacy_ids": list(fields.get("legacy_ids", [])),
        "group_tree": [
            {
                "id": group_id,
                "title": group_title,
                "description": fields.get(
                    "group_description", "<GroupDescription></GroupDescription>"
                ),
            }
        ],
    }
    if fields.get("group_id_src"):
        extra["group_id_src"] = fields["group_id_src"]
    for name in _STRING_FIELDS:
        extra[name] = fields.get(name) or ""
    for name in NULL_WHEN_EMPTY:
        extra[name] = fields.get(name) or None
    return Rule(
        group_id=group_id,
        rule_id=pretty_rule_id(rule_id_src),
        rule_id_src=rule_id_src,
        rule_version=rule_version,
        rule_title=rule_title,
        severity=severity,
        status=status,
        uuid=new_id(),
        comments=comments,
        finding_details=finding_details,
        overrides={},
        ccis=list(ccis),
        extra=extra,
    )


def make_stig(
    *,
    new_id: IdFactory,
    stig_name: str,
    stig_id: str,
    release_info: str,
    rules: list[Rule],
    version: int | str | None,
    display_name: str = "",
    stig_uuid: str | None = None,
) -> Stig:
    """Build a Stig. Pass `stig_uuid` when rules were already built against that uuid.

    `reference_identifier` is the first rule's, per the schema's description of the field.
    """
    first = rules[0].extra.get("reference_identifier") if rules else None
    return Stig(
        stig_name=stig_name,
        display_name=display_name or stig_name,
        stig_id=stig_id,
        release_info=release_info,
        rules=rules,
        version=version,
        write_version=False,
        uuid=stig_uuid or new_id(),
        extra={"reference_identifier": first, "size": len(rules)},
    )


def make_checklist(
    *, new_id: IdFactory, title: str, target_data: dict[str, Any], stigs: list[Stig]
) -> Checklist:
    return Checklist(
        title=title,
        id=new_id(),
        target_data=target_data,
        stigs=stigs,
        extra={"cklb_version": CKLB_VERSION, "active": False, "mode": 1, "has_path": True},
    )
