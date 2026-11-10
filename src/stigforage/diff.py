"""Rule matching and checklist comparison.

`match_rules` is the single place that decides which rule in one STIG corresponds to which rule
in another. `merge` and `upgrade` reuse it, because a wrong match silently
carries a review status onto a different control, so there must be exactly one implementation.

Matching policy (maintainer-approved, ADR 0002):
1. exact `rule_id_src` (falling back to `rule_id` when absent), unique on both sides;
2. otherwise `group_id` (the V-number), but only when exactly one unmatched rule on each side
   carries it. Anything ambiguous stays unmatched and is reported, never guessed.
No title or CCI similarity matching: a fuzzy match is worse than an honest "unmatched".

Pure functions only: no I/O, no logging.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from stigforage.model import Checklist, Rule, Stig

__all__ = [
    "CONTENT_FIELDS",
    "REVIEW_FIELDS",
    "ChecklistDiff",
    "FieldChange",
    "Matching",
    "RuleDiff",
    "StigDiff",
    "diff_checklists",
    "diff_stigs",
    "match_rules",
    "pair_stigs",
    "rule_field",
]

MatchedBy = Literal["rule_id_src", "group_id"]

# Fields that describe the control itself (change between STIG releases) ...
CONTENT_FIELDS = (
    "rule_id", "rule_version", "severity", "rule_title", "ccis",
    "check_content", "fix_text", "discussion",
)  # fmt: skip
# ... and fields that hold the assessor's work.
REVIEW_FIELDS = ("status", "comments", "finding_details")


@dataclass(frozen=True)
class FieldChange:
    """One differing field. Values are as stored; display code decides how to abbreviate."""

    name: str
    old: Any
    new: Any


@dataclass
class RuleDiff:
    old: Rule
    new: Rule
    matched_by: MatchedBy
    changes: list[FieldChange] = field(default_factory=list)


@dataclass
class Matching:
    pairs: list[tuple[Rule, Rule, MatchedBy]] = field(default_factory=list)
    old_only: list[Rule] = field(default_factory=list)
    new_only: list[Rule] = field(default_factory=list)
    # group_ids that could not be matched because several unmatched rules share them.
    ambiguous: list[str] = field(default_factory=list)


@dataclass
class StigDiff:
    stig_id: str
    old_release: str
    new_release: str
    matching: Matching
    rules: list[RuleDiff] = field(default_factory=list)

    @property
    def unchanged(self) -> int:
        return sum(1 for r in self.rules if not r.changes)


@dataclass
class ChecklistDiff:
    stigs: list[StigDiff] = field(default_factory=list)
    old_only_stigs: list[str] = field(default_factory=list)
    new_only_stigs: list[str] = field(default_factory=list)


def rule_field(rule: Rule, name: str) -> Any:
    """Read a diffable field, normalising None to "" so absent and empty compare equal."""
    if name in {"check_content", "fix_text", "discussion"}:
        value = rule.extra.get(name)
    elif name == "status":
        return rule.status
    else:
        value = getattr(rule, name)
    return "" if value is None else value


def _match_key(rule: Rule) -> str:
    return rule.rule_id_src or rule.rule_id


def _unique_index(rules: Iterable[Rule], key: Any) -> dict[str, Rule]:
    """Index by key, dropping keys that occur more than once (ambiguous, never guessed)."""
    seen: defaultdict[str, list[Rule]] = defaultdict(list)
    for rule in rules:
        seen[key(rule)].append(rule)
    return {k: v[0] for k, v in seen.items() if len(v) == 1}


def match_rules(old: list[Rule], new: list[Rule]) -> Matching:
    """Pair rules between two releases of the same STIG. Output order follows `old`, then `new`."""
    result = Matching()
    old_by_id = _unique_index(old, _match_key)
    new_by_id = _unique_index(new, _match_key)
    paired_old: set[int] = set()
    paired_new: set[int] = set()
    for rule in old:
        counterpart = new_by_id.get(_match_key(rule))
        if counterpart is not None and old_by_id.get(_match_key(rule)) is rule:
            result.pairs.append((rule, counterpart, "rule_id_src"))
            paired_old.add(id(rule))
            paired_new.add(id(counterpart))

    rest_old = [r for r in old if id(r) not in paired_old]
    rest_new = [r for r in new if id(r) not in paired_new]
    old_by_group = _unique_index(rest_old, lambda r: r.group_id)
    new_by_group = _unique_index(rest_new, lambda r: r.group_id)
    ambiguous: set[str] = set()
    for rule in rest_old:
        counterpart = new_by_group.get(rule.group_id)
        if counterpart is not None and old_by_group.get(rule.group_id) is rule:
            result.pairs.append((rule, counterpart, "group_id"))
            paired_old.add(id(rule))
            paired_new.add(id(counterpart))
        elif any(r.group_id == rule.group_id for r in rest_new):
            ambiguous.add(rule.group_id)

    result.old_only = [r for r in old if id(r) not in paired_old]
    result.new_only = [r for r in new if id(r) not in paired_new]
    result.ambiguous = sorted(ambiguous)
    return result


def _diff_rule(old: Rule, new: Rule, matched_by: MatchedBy) -> RuleDiff:
    diff = RuleDiff(old, new, matched_by)
    for name in (*CONTENT_FIELDS, *REVIEW_FIELDS):
        before, after = rule_field(old, name), rule_field(new, name)
        if before != after:
            diff.changes.append(FieldChange(name, before, after))
    return diff


def diff_stigs(old: Stig, new: Stig) -> StigDiff:
    matching = match_rules(old.rules, new.rules)
    return StigDiff(
        stig_id=new.stig_id,
        old_release=old.release_info,
        new_release=new.release_info,
        matching=matching,
        rules=[_diff_rule(o, n, by) for o, n, by in matching.pairs],
    )


def pair_stigs(
    old: list[Stig], new: list[Stig]
) -> tuple[list[tuple[Stig, Stig]], list[str], list[str]]:
    """Pair STIGs on `stig_id`. Returns (pairs, stig_ids only in old, stig_ids only in new).

    A repeated `stig_id` within one checklist is paired in order of appearance. `diff` and
    `merge` both use this, so they always agree on which STIGs correspond.
    """
    remaining: defaultdict[str, list[Stig]] = defaultdict(list)
    for stig in new:
        remaining[stig.stig_id].append(stig)
    pairs: list[tuple[Stig, Stig]] = []
    old_only: list[str] = []
    for stig in old:
        candidates = remaining.get(stig.stig_id)
        if candidates:
            pairs.append((stig, candidates.pop(0)))
        else:
            old_only.append(stig.stig_id)
    new_only = [s.stig_id for group in remaining.values() for s in group]
    return pairs, old_only, new_only


def diff_checklists(old: Checklist, new: Checklist) -> ChecklistDiff:
    """Compare two checklists STIG by STIG (paired by `pair_stigs`)."""
    pairs, old_only, new_only = pair_stigs(old.stigs, new.stigs)
    return ChecklistDiff([diff_stigs(o, n) for o, n in pairs], old_only, new_only)
