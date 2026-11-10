"""Carry reviews from a checklist onto a new release of its STIGs (`upgrade`).

Policy (ADR 0002 point 3 and its addendum):
- OUTPUT takes its structure from the new benchmark and its asset data, title and checklist id
  from OLD. Reviews are the review unit `merge` defines, matched through `diff.match_rules`.
- When a rule's check text changed (compared after collapsing whitespace, because DISA often
  reflows text without changing it), its status is downgraded to `not_reviewed` and a note naming
  both releases is prepended to the comments, unless `keep_status_on_change` is set. Finding
  details and overrides are kept. Severity changes are reported but never downgrade.
- OLD STIGs absent from the new benchmark carry over unchanged; STIGs only in the new benchmark
  are reported, not added. A new benchmark that already holds reviews is refused.

Pure functions only: no I/O, no logging. Inputs are never mutated; the result holds copies.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Literal

from stigforage.diff import match_rules, pair_stigs
from stigforage.merge import copy_review, is_empty_review, same_release
from stigforage.model import Checklist, ChecklistError, Rule, Status, Stig

__all__ = [
    "CheckChange",
    "SeverityChange",
    "StigUpgrade",
    "UpgradeResult",
    "upgrade_checklist",
]

CheckAction = Literal["downgraded", "kept", "was_not_reviewed"]


@dataclass(frozen=True)
class CheckChange:
    """A reviewed rule whose check text changed, and what was done about it."""

    group_id: str
    rule_id: str
    old_status: Status
    action: CheckAction


@dataclass(frozen=True)
class SeverityChange:
    group_id: str
    rule_id: str
    old: str
    new: str


@dataclass
class StigUpgrade:
    stig_id: str
    old_release: str
    new_release: str
    same_release: bool
    matched: int = 0
    carried: int = 0  # reviews carried with their status (includes `kept` check changes)
    downgraded: int = 0
    matched_by_group_id: int = 0
    check_changes: list[CheckChange] = field(default_factory=list)
    severity_changes: list[SeverityChange] = field(default_factory=list)
    added: list[Rule] = field(default_factory=list)
    removed: int = 0
    # Removed rules that held a review: that work has no rule to go to in the new release.
    lost: list[Rule] = field(default_factory=list)
    ambiguous: list[str] = field(default_factory=list)


@dataclass
class UpgradeResult:
    checklist: Checklist
    stigs: list[StigUpgrade] = field(default_factory=list)
    unchanged_stigs: list[str] = field(default_factory=list)  # OLD only: carried over as is
    new_only_stigs: list[str] = field(default_factory=list)  # new benchmark only: not added


def _check_text(rule: Rule) -> str:
    value = rule.extra.get("check_content")
    return " ".join(value.split()) if isinstance(value, str) else ""


def _release_name(stig: Stig) -> str:
    return stig.release_info.strip() or (
        f"version {stig.version}" if stig.version is not None else "an unknown release"
    )


def _downgrade_note(old_rule: Rule, old: Stig, new: Stig) -> str:
    # No date, so the same inputs always produce the same output.
    reason = (
        f"the check text changed in {_release_name(new)}"
        if _check_text(old_rule)
        else f"the old checklist has no check text to compare with {_release_name(new)}"
    )
    return (
        f"[stigforage upgrade] Status was {old_rule.status.value} under {_release_name(old)}; "
        f"{reason}. Re-review required."
    )


def _refuse_reviewed_benchmark(new: Checklist) -> None:
    for stig in new.stigs:
        for rule in stig.rules:
            if not is_empty_review(rule):
                raise ChecklistError(
                    f"NEW_BENCHMARK STIG {stig.stig_id!r} rule {rule.group_id} already holds a "
                    "review; upgrade expects a blank benchmark (use merge to combine reviewed "
                    "checklists)"
                )


def _carry(
    old_rule: Rule, new_rule: Rule, old: Stig, new: Stig, keep: bool, rep: StigUpgrade
) -> None:
    """Carry one matched rule's review onto the new release, recording what happened."""
    if old_rule.severity != new_rule.severity:
        rep.severity_changes.append(
            SeverityChange(
                new_rule.group_id, new_rule.rule_id, old_rule.severity, new_rule.severity
            )
        )
    if is_empty_review(old_rule):
        return
    copy_review(old_rule, new_rule)
    # Already at this release: nothing changed, whatever the check text holds (ADR addendum).
    old_text = _check_text(old_rule)
    unchanged = bool(old_text) and old_text == _check_text(new_rule)
    if rep.same_release or unchanged:
        rep.carried += 1
        return
    action: CheckAction
    if old_rule.status == Status.NOT_REVIEWED:
        action = "was_not_reviewed"
        rep.carried += 1
    elif keep:
        action = "kept"
        rep.carried += 1
    else:
        action = "downgraded"
        rep.downgraded += 1
        note = _downgrade_note(old_rule, old, new)
        new_rule.status = Status.NOT_REVIEWED
        new_rule.comments = f"{note}\n\n{new_rule.comments}" if new_rule.comments else note
    rep.check_changes.append(
        CheckChange(new_rule.group_id, new_rule.rule_id, old_rule.status, action)
    )


def _upgrade_stig(old: Stig, new: Stig, keep: bool) -> tuple[Stig, StigUpgrade]:
    out = copy.deepcopy(new)
    rep = StigUpgrade(
        old.stig_id,
        old.release_info,
        new.release_info,
        same_release=same_release(old, new) and bool(new.release_info.strip()),
    )
    matching = match_rules(old.rules, out.rules)
    rep.matched = len(matching.pairs)
    rep.added = matching.new_only
    rep.removed = len(matching.old_only)
    rep.lost = [r for r in matching.old_only if not is_empty_review(r)]
    rep.ambiguous = matching.ambiguous
    for old_rule, new_rule, matched_by in matching.pairs:
        if matched_by == "group_id":
            rep.matched_by_group_id += 1
        _carry(old_rule, new_rule, old, out, keep, rep)
    return out, rep


def upgrade_checklist(
    old: Checklist, new: Checklist, *, keep_status_on_change: bool = False
) -> UpgradeResult:
    """Return OLD's reviews carried onto NEW's release, plus a report.

    Raises ChecklistError, before any work, if NEW already holds a review.
    """
    _refuse_reviewed_benchmark(new)
    pairs, old_only, new_only = pair_stigs(old.stigs, new.stigs)
    upgraded: dict[int, tuple[Stig, StigUpgrade]] = {
        id(o): _upgrade_stig(o, n, keep_status_on_change) for o, n in pairs
    }
    return UpgradeResult(
        Checklist(
            title=old.title,
            id=old.id,
            target_data=copy.deepcopy(old.target_data),
            # OLD's order is kept; STIGs the new benchmark lacks carry over untouched.
            stigs=[
                upgraded[id(s)][0] if id(s) in upgraded else copy.deepcopy(s) for s in old.stigs
            ],
            extra=copy.deepcopy(old.extra),
        ),
        stigs=[rep for _, rep in upgraded.values()],
        unchanged_stigs=old_only,
        new_only_stigs=new_only,
    )
