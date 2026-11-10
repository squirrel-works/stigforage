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

## Addendum (2026-11-09): decisions for units 2 and 3

Accepted by maintainer before unit 2 began.

### Point 2 refined: the review unit

- Superseded: point 2's conflict rule, "both sides hold a status other than `not_reviewed` and
  they differ".
- Evidence: that rule leaves two cases undefined: the same status with different comments or
  finding details, and a `not_reviewed` target that already holds notes. Read literally, the
  target wins both silently and SOURCE's text is dropped without being reported.
- Replacement: status, comments, finding details and overrides form one review unit. A unit is
  empty when the status is `not_reviewed` and the other three are empty (`None` equals `""`).
  An empty target unit receives SOURCE's unit whole. When both units have content and differ, it
  is a listed conflict: the target wins unless `--prefer source` is given.

### Unit 2 (`merge`)

- STIGs pair on `stig_id` exactly as `diff` pairs them; rules pair through `match_rules` only.
- Refused when a paired STIG is a different release in SOURCE and TARGET (`release_info`
  differs, or `version` differs where both have one). Moving reviews across releases is
  `upgrade`'s job, because it checks whether the check text changed.
- A host name mismatch is a warning and the merge proceeds: applying a template checklist's
  reviews to many hosts is a legitimate use.
- Overrides are carried verbatim as part of the review unit. This is CKLB to CKLB and never
  interprets the unverified override layout.
- TARGET's structure and asset data win. Rules and STIGs found only in SOURCE are reported,
  never added.
- Same conventions as `convert`: dry run by default, OUTPUT may not be either input, exit 0 even
  when conflicts exist.

### Unit 3 (`upgrade`)

- A non-interactive command, `upgrade OLD NEW_BENCHMARK -o OUTPUT`, with a dry-run report and
  `--apply`. The roadmap's "upgrade wizard" means this command; interactive steps belong to the
  V1.x GUI.
- "Check text changed" compares `check_content` only, after collapsing whitespace, because DISA
  often reflows text without changing it. Severity changes are reported but do not downgrade.
- The downgrade note is prepended to the comments and names the old and new release. It carries
  no date, so output is reproducible.
- In a checklist with several STIGs, only those present in the new benchmark are upgraded; the
  rest carry over unchanged.
