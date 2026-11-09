# ADR 0002: Rule matching, merge conflicts and upgrade policy (V0.2.2)

Status: accepted by maintainer (all three proposals approved as written).

1. Rule matching (`diff.match_rules`, the only implementation; merge and upgrade reuse it):
   exact `rule_id_src` (or `rule_id` when absent), then `group_id`, and only when exactly one
   unmatched rule on each side carries it. Ambiguous or duplicate keys are left unmatched and
   reported, never guessed. No title or CCI similarity: a wrong match carries a review status
   onto a different control, which is worse than an honest "unmatched".
2. `merge` conflicts: when both sides hold a status other than `not_reviewed` and they differ,
   the target wins and the conflict is listed. `--prefer source` is an explicit override.
3. `upgrade`: when a rule's check text changed between releases, the status is downgraded to
   `not_reviewed` with a note in the comments, unless `--keep-status-on-change` is given.
   Stricter than Workbench is likely to be, deliberately: an assessment must not claim a finding
   still holds against text it was not made against.

## Unit 1 notes (`diff`)

- Read-only. Exit 0 whether or not differences exist: exit 1 already means "validation errors"
  in this CLI, and overloading it would break scripts that distinguish the two.
- Long text fields are shown by size only (`<123 chars> -> <45 chars>`), never dumped.
- `None` and `""` compare equal, because importers differ in which they produce.
- Not verified: how often real consecutive DISA releases change `rule_id_src` yet keep
  `group_id`. The `group_id` step exists for that case; the ASD V6R5 ZIP is the only real release
  available so far, and no older release has been diffed against it.
