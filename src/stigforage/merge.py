"""Carry review state from one checklist into another of the same STIG release (`merge`).

Policy (ADR 0002 point 2 and its addendum):
- Status, comments, finding details and overrides form one review unit. A unit is empty when the
  status is `not_reviewed` and the rest are empty; `None` and `""` are equal.
- An empty TARGET unit receives SOURCE's unit whole. When both units have content and differ,
  the conflict is listed and TARGET wins unless `prefer="source"`.
- STIGs pair through `diff.pair_stigs` and rules through `diff.match_rules`, the only
  implementations. Paired STIGs must be the same release; anything else is `upgrade`'s job.
- TARGET's structure and asset data win: rules and STIGs found only in SOURCE are reported,
  never added.

Pure functions only: no I/O, no logging. Inputs are never mutated; the result holds a copy.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Literal

from stigforage.diff import match_rules, pair_stigs
from stigforage.model import Checklist, ChecklistError, Rule, Status, Stig

__all__ = ["Conflict", "MergeResult", "Prefer", "StigMerge", "merge_checklists"]

Prefer = Literal["target", "source"]

_UNIT_FIELDS = ("status", "comments", "finding_details", "overrides")


@dataclass(frozen=True)
class Conflict:
    """A rule whose review differs between SOURCE and TARGET, both non-empty."""

    group_id: str
    rule_id: str
    target_status: Status
    source_status: Status
    differs: tuple[str, ...]  # which review-unit fields differ


@dataclass
class StigMerge:
    stig_id: str
    release_info: str
    carried: int = 0
    unchanged: int = 0
    matched_by_group_id: int = 0
    conflicts: list[Conflict] = field(default_factory=list)
    # SOURCE rules that hold a review but have no counterpart in TARGET: that work is not carried.
    not_carried: list[Rule] = field(default_factory=list)
    ambiguous: list[str] = field(default_factory=list)


@dataclass
class MergeResult:
    checklist: Checklist
    prefer: Prefer
    stigs: list[StigMerge] = field(default_factory=list)
    source_only_stigs: list[str] = field(default_factory=list)
    target_only_stigs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _unit(rule: Rule) -> dict[str, Any]:
    return {
        "status": rule.status,
        "comments": rule.comments or "",
        "finding_details": rule.finding_details or "",
        "overrides": rule.overrides,
    }


_EMPTY_UNIT = {
    "status": Status.NOT_REVIEWED,
    "comments": "",
    "finding_details": "",
    "overrides": {},
}


def _is_empty(rule: Rule) -> bool:
    return _unit(rule) == _EMPTY_UNIT


def _copy_review(source: Rule, target: Rule) -> None:
    target.status = source.status
    # "" rather than None: the DISA schema requires these to be strings.
    target.comments = source.comments or ""
    target.finding_details = source.finding_details or ""
    target.overrides = copy.deepcopy(source.overrides)


def _describe(stig: Stig) -> str:
    version = f"version {stig.version}, " if stig.version is not None else ""
    return f"{version}{stig.release_info.strip() or 'no release info'}"


def _check_release(source: Stig, target: Stig, warnings: list[str]) -> None:
    """Raise unless both sides are the same release; warn when that cannot be verified."""
    versions_differ = (
        source.version is not None
        and target.version is not None
        and str(source.version) != str(target.version)  # "2" and 2 are the same version
    )
    if source.release_info.strip() != target.release_info.strip() or versions_differ:
        raise ChecklistError(
            f"STIG {target.stig_id!r}: SOURCE is {_describe(source)} but TARGET is "
            f"{_describe(target)}; merge only combines reviews of the same release "
            "(use upgrade to move reviews to a new release)"
        )
    if not target.release_info.strip():
        warnings.append(
            f"STIG {target.stig_id!r}: neither side has release info, so the release match "
            "could not be verified"
        )


def _check_hosts(source: Checklist, target: Checklist, warnings: list[str]) -> None:
    src, tgt = source.host_name.strip(), target.host_name.strip()
    # Host names are case-insensitive. A blank side (e.g. a benchmark) is not a mismatch.
    if src and tgt and src.casefold() != tgt.casefold():
        warnings.append(
            f"SOURCE host {src!r} differs from TARGET host {tgt!r}; reviews are merged anyway"
        )


def _merge_stig(source: Stig, target: Stig, prefer: Prefer) -> StigMerge:
    result = StigMerge(target.stig_id, target.release_info)
    matching = match_rules(source.rules, target.rules)
    result.ambiguous = matching.ambiguous
    result.not_carried = [r for r in matching.old_only if not _is_empty(r)]
    for src, tgt, matched_by in matching.pairs:
        if matched_by == "group_id":
            result.matched_by_group_id += 1
        src_unit, tgt_unit = _unit(src), _unit(tgt)
        if _is_empty(src) or src_unit == tgt_unit:
            result.unchanged += 1
        elif _is_empty(tgt):
            _copy_review(src, tgt)
            result.carried += 1
        else:
            differs = tuple(n for n in _UNIT_FIELDS if src_unit[n] != tgt_unit[n])
            result.conflicts.append(
                Conflict(tgt.group_id, tgt.rule_id, tgt.status, src.status, differs)
            )
            if prefer == "source":
                _copy_review(src, tgt)
    return result


def merge_checklists(
    source: Checklist, target: Checklist, *, prefer: Prefer = "target"
) -> MergeResult:
    """Return a copy of `target` with `source`'s reviews merged in, plus a report.

    Raises ChecklistError, before any merging, if a paired STIG is a different release.
    """
    output = copy.deepcopy(target)
    result = MergeResult(output, prefer)
    _check_hosts(source, target, result.warnings)
    pairs, result.source_only_stigs, result.target_only_stigs = pair_stigs(
        source.stigs, output.stigs
    )
    for src_stig, out_stig in pairs:
        _check_release(src_stig, out_stig, result.warnings)
    result.stigs = [_merge_stig(src, out, prefer) for src, out in pairs]
    return result
