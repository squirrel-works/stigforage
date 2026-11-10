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

## Evidence from real releases (2026-11-10)

Two consecutive DISA releases were downloaded from `dl.dod.cyber.mil` for a manual check. They
stay outside the repository, which bundles no DISA content, so this is not part of the suite.

- Files: `U_RHEL_9_V2R9_STIG.zip` (SHA-256 `1875de2543d0...286ca1ae`) and
  `U_RHEL_9_V2R10_STIG.zip` (SHA-256 `a9a212444ac3...792945c3d111`), 445 rules each.
- Matching: 237 rules matched on `rule_id_src` and 206 on `group_id`, with none ambiguous. Every
  one of the 206 was a rule revision bump, and 153 of them changed nothing else that `diff`
  compares. This answers the unit 1 question above: without the `group_id` step, almost half the
  reviews would have been dropped.
- Check text: `check_content` differed in 26 rules, but only 23 after collapsing whitespace. The
  other 3 were reflowed only, so whitespace collapsing prevented 3 false downgrades.
- `upgrade` of a fully reviewed V2R9 checklist to V2R10: 443 matched, 420 carried, 23
  downgraded (exactly the 23 real check changes), 2 rules added, and 2 removed with their reviews
  reported as lost. The output validates against the DISA CKLB schema. `--keep-status-on-change`
  carried all 443, and upgrading to V2R9 itself reported "already at this release".
- Not covered: this is one STIG and one release step. Severity did not change in this pair, so
  that path is still tested on synthetic data only.

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

Added before unit 3 began (maintainer-approved, 2026-11-10):

- A new benchmark that already holds a review (for example a reviewed `.cklb`) is refused, with a
  pointer to `merge`: its reviews would otherwise be overwritten wherever OLD has one.
- STIGs present only in the new benchmark are reported, not added, matching `merge`.
- An OLD STIG already at the new benchmark's release is allowed. Nothing changed, so every
  review carries over and the report says it is already at that release.

Implementation details, consistent with the above:

- OUTPUT takes its structure from the new benchmark and its asset data, title and checklist id
  from OLD. The review unit is the one `merge` defines.
- On a downgrade, finding details and overrides are kept; only the status changes and the note
  is prepended. A rule whose status was already `not_reviewed` gets no note.
- An OLD rule with no check text cannot be compared, so it is treated as changed (the safe
  direction) and the note says why.
