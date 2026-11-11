# ADR 0003: Result importers (V0.3.3)

Status: all ten decisions accepted by maintainer (2026-11-10; decision 9 confirmed after unit 1).

## Evidence

From real samples: the public test files of STIG Manager (MIT) and MITRE Heimdall (Apache-2.0),
and DISA's RHEL 9 V2R10 SCAP 1.3 benchmark and manual STIG, downloaded for comparison and not
bundled.

- SCC and Evaluate-STIG write an XCCDF 1.2 `Benchmark` holding a `TestResult`. Rule results
  name rules as `xccdf_mil.disa.stig_rule_SV-...r..._rule`. Evaluate-STIG output has no `Group`
  elements, so no V-numbers.
- The SCAP benchmark and the manual STIG of the same release differ in every identifier: STIG id
  (`xccdf_mil.disa.stig_benchmark_RHEL_9_STIG` vs `RHEL_9_STIG`), version (`002.010` vs `2`)
  and release info (no "Release: 10" in the SCAP one). All 393 SCAP rules pair with the manual
  STIG by V-number, but 156 carry a different rule revision, and no check text matches (SCAP
  checks point to OVAL).
- Benchmark versions seen: `V2R5` (STIG Manager), `V2R9` (Evaluate-STIG), `6.3.3` (SCC
  enhanced content "based on Release: 6.3"), `002.010` (DISA SCAP). The manual STIG has `2` plus
  "Release: 10" in its release info.
- Finding text: SCC and Evaluate-STIG use `<message>`; STIG Manager exports put a `<detail>`
  element in `check-content`.
- STIG Manager imports only `pass`, `fail` and `notapplicable` as reviews by default; every
  other result is treated as unreviewed.
- InSpec HDF control `id` is the V-number and `tags.rid` the rule id. SARIF (Flawfinder sample),
  pip-audit and npm audit carry no STIG identifiers.
- The DISA SCAP 1.3 data stream loads through the existing benchmark path (393 rules). ADR 0001
  listed that path as tested only with a synthetic wrapper; this is its first real file.
- Trivy, Grype and OSV-Scanner can all write SARIF (writers present in each project's source;
  OSV-Scanner documents `--format sarif`). pip-audit writes JSON or CycloneDX, npm audit JSON.

## Decisions

1. Command: `import-results CHECKLIST RESULTS... -o OUTPUT`, reusing the review logic and the
   dry-run and output path of `merge`. `merge` itself stays strict. Each RESULTS file applies to
   the STIG it pairs with; two files pairing with the same STIG are refused.
2. XCCDF results: `pass` -> `not_a_finding`, `fail` -> `open`, `notapplicable` ->
   `not_applicable`. Every other result (notchecked, error, unknown, notselected, informational,
   fixed) is not imported and is counted in the report. This matches STIG Manager's default.
3. HDF: any failed result -> `open`; all passed -> `not_a_finding`; impact 0 ->
   `not_applicable`. Skipped-only or error results are not imported and are reported.
4. Conflicts: the checklist wins by default and conflicts are listed; `--prefer results` lets
   the scan win.
5. A scan writes the status and replaces the finding details with a source line (tool, scan
   time, result) followed by the scanner's messages. Comments and overrides are never touched.
6. Pairing: the STIG id drops the `xccdf_mil.disa.stig_benchmark_` prefix. Releases compare as
   (version, release) numbers, and a mismatch is refused. Rules match through
   `diff.match_rules`: exact rule id (prefix dropped), then V-number. A file without V-numbers
   can therefore only match exact rule ids. Unmatched rules are reported, never guessed.
7. Host: a scan whose host does not match the checklist's is refused unless
   `--allow-host-mismatch` is given, which turns the refusal into a warning.
8. SARIF and dependency audits: the user names the rule (`--rule V-xxxxxx`) and a summary of the
   findings is attached to it. Any finding makes it `open`; no findings leaves the status alone,
   because a clean scan does not prove compliance. No mapping file.
9. No separate "CVE JSON" format. The SARIF importer covers
   Trivy, Grype and OSV-Scanner; unit 4 covers pip-audit and npm audit JSON only.
10. Fixtures come from STIG Manager (MIT, already credited) and Heimdall (Apache-2.0, credited in
    NOTICE when first used). npm audit and pip-audit output is generated here. ARF uses a
    synthetic wrapper around a real result unless a real SCC ARF file is supplied.
    Update during unit 1 (maintainer-approved): no SCC download is available without DoD
    credentials, so a real ARF was generated with OpenSCAP instead (see "Real ARF" below). The
    synthetic wrapper stays for the layout with the Benchmark inside the report, which OpenSCAP
    does not write.

## Real ARF (2026-11-10)

OpenSCAP 1.3.14 in a Red Hat UBI 9 container (RHEL 9.8) scanned itself against DISA's RHEL 9
V2R10 SCAP 1.3 benchmark, profile `MAC-1_Classified`, writing ARF (9.7 MB).

- Layout: the TestResult sits in `reports`, the Benchmark inside a data stream in
  `report-requests`, plus `assets` and two OVAL result reports.
- stigforage read it unchanged: RHEL_9_STIG, release (2, 10) from `002.010`, 393 results, all
  with V-numbers taken from the separate Benchmark.
- Imported into a blank checklist of the manual V2R10 STIG: 378 applied, 15 `error` results
  not imported, 0 unmatched, no warnings. 156 rules matched by V-number only, the same 156
  revision differences found by comparing the two benchmarks directly.
- The fixture keeps 10 of those rules (3 pass, 3 fail, 2 notapplicable, 2 error) with the
  structure intact. OVAL components and reports were removed, and the container's name,
  addresses and MAC were replaced with documentation values (RFC 5737, RFC 3849, RFC 7042). A
  matching 10-rule blank checklist of the manual STIG makes it an end-to-end test: 8 applied, 7
  by V-number.

## Unit 2: HDF (maintainer-approved after review, 2026-11-10)

Evidence from seven Heimdall samples (InSpec 1.37 to 4.52, plus Heimdall-converted checklists):

- No DISA benchmark id. Profile names are free text (`disa_stig-el7`, `Red Hat Enterprise Linux
  7 STIG`, `RHEL_9_STIG`, `redhat-enterprise-linux-7-stig-baseline`); control ids are V-numbers.
- Release appears in 3 of 7: a `vNrN` in the profile title (2) or a `STIGRef` tag ("Version 1,
  Release: 3", 1). The profile version is not a STIG release: `0.2.0` sits beside "v1r4".
- No host name anywhere; `platform` is the operating system.
- Overlays: up to three profiles linked by `parent_profile`/`depends`. Only the base profile
  holds results; the outer layers repeat every control without them. In both overlay samples
  every control has the same impact in every layer.

Decisions, made during implementation because decisions 1-10 do not cover HDF's missing
identifiers:

- An HDF scan pairs with the one checklist STIG holding its V-numbers. None, or V-numbers spread
  over several STIGs, is refused.
- Release from `STIGRef`, else from a `vNrN` in the title, else unknown (a warning, per the
  rule for unknown releases above).
- The host is never checked; a checklist with a host name gets a warning.
- Overlays: see "Revised to match Heimdall" below.
- Control status: see "Revised to match Heimdall" below.
- Finding details list each test as `[status] code_desc: message`. The scan time is the latest
  result's start time, since HDF records no end time.
- When the release cannot be compared and any matched rule's revision differs from the
  checklist's, a warning gives the count ("3 of 10 matched rules have a different rule
  revision"). InSpec STIG profiles take rule ids from the manual STIG, so a revision mismatch
  is a real sign of release drift; the real V1R3 sample against the V1R1 fixture shows 3 of 10.
  A warning only, with no threshold. It applies to any scan whose release is unknown.

### Revised to match Heimdall

- Superseded: decision 3 as first implemented ("impact 0 -> notapplicable; else any failed ->
  fail, even alongside errors; else all passed -> pass; passed mixed with skipped not
  imported"), and the unit 2 overlay rule ("impact from the outermost profile").
- Evidence: Heimdall's own status code (`libs/inspecjs/src/compat_impl/compat_inspec_1_0.ts`,
  `compute_status`) applies, first match wins: any error result, including any result with a
  backtrace -> Profile Error; waived (`waiver_data.skipped_due_to_waiver`) or impact 0 -> Not
  Applicable; no results -> Profile Error; any failed -> Failed; any passed -> Passed; skipped
  -> Not Reviewed. Its overlay code (`context.ts`) reads every control's data from the base
  ("root") control. The first implementation disagreed with Heimdall on failed with an error,
  passed with a skip, impact 0 with an error, waived controls, and backtraces. On the real
  samples that moved 1 to 3 passed-with-skipped controls per file to `pass`, and two failing
  controls whose results carry backtraces (one RHEL 7 run, one Ubuntu run) to `error`.
- Replacement: Heimdall's order, so a checklist agrees with what HDF users see in Heimdall,
  with one exception. A waived control is not imported and is counted as `waived`, where
  Heimdall shows Not Applicable: a waiver accepts the risk of a requirement that does apply,
  which belongs in an open finding with a POA&M, not N/A, so the assessor decides. Imported:
  `fail`, `pass`, `notapplicable`. Counted, not imported: `error`, `waived`, `no_results`,
  `skipped`. Impact and everything else come from the control that ran (the base profile);
  outer layers name the scan and may give the release in their title, searched outermost
  first. Attestations are left alone, as Heimdall's status code also leaves them. No sample
  has waiver data, so the waiver path is tested on synthetic data only.

## Unit 3: SARIF (details within decision 8, maintainer-approved after review, 2026-11-10)

Evidence from four real files: Flawfinder 2.0.15 (via Heimdall), and the Trivy and Grype
projects' own SARIF test outputs.

- Severity is the SARIF `level` (error, warning, note). Seven Flawfinder results have no level
  and rely on the rule's `defaultConfiguration`, as SARIF 2.1.0 allows; with neither, the spec
  default is `warning`.
- Vulnerability scanners use the CVE as the rule id and add a `security-severity` property.
  Messages can span lines (Trivy).
- None uses `kind`, `suppressions` or `baselineState`, and none records an invocation time or a
  machine.

Details, made during implementation:

- `--rule V-NUMBER` names one checklist rule per run. Every SARIF file in the run (`.sarif` or
  `.sarif.json`) is evidence for it, combined into one scan, so several scanners can back one
  rule. SARIF without `--rule`, or `--rule` without SARIF, is refused.
- The rule's V-number picks the checklist STIG, through the same pairing as HDF. A SARIF scan
  and an XCCDF or HDF scan of that same STIG in one run are refused by decision 1; run them
  separately.
- A finding is a result with `kind` `fail` (the default), not suppressed (a suppression whose
  status is `accepted` or absent), and not `baselineState` `absent`. `kind` `review` or `open`
  needs a person, so it is not a finding. Results not counted are tallied by reason.
- Every level counts, `note` included, as decision 8 says ("any finding"). On Flawfinder's
  sample that includes 35 `note` results, and Grype rates a low CVE `note`, so a rule may turn
  `open` on low-severity findings alone. A level threshold was raised at review and declined:
  every level counts, with no option to filter.
- Finding details hold, per tool, the counts by level, then up to 50 findings as
  `CVE-x [level] message (path:line)`, then "... and N more". Counts stay complete.
- Release and host cannot be checked, so both warn, as for HDF. A SARIF scan always matches by
  V-number because it names no rule id, so the drift warning counts only matches where the scan
  gave a rule id that differs.

## Unit 4: pip-audit and npm audit (details within decisions 8 and 9, pending maintainer review)

Evidence from real output generated for this project: pip-audit 2.10.1 on old requests,
urllib3 and jinja2 plus a name not on PyPI, and npm 11.20.0 audit of old lodash, minimist and
mkdirp; each with a clean counterpart.

- pip-audit JSON is `dependencies[]`, each with `vulns[]` (`id`, `aliases`, `fix_versions`,
  `description`), and a `fixes` list. It has no severity. It listed 47 entries for 24 distinct
  vulnerabilities: most appear twice. A package it cannot audit gets a `skip_reason` instead.
- npm audit (report version 2) is keyed by package. Each entry's `via` holds advisory objects
  (GHSA URL, title, severity, range) or the names of other vulnerable packages. npm counted 3
  vulnerable packages; they carry 10 advisory entries, 8 distinct per package (minimist lists
  two advisories twice, with different ranges). mkdirp is vulnerable only through minimist.

Details, made during implementation:

- Same mechanism as SARIF: every audit file in a run joins the SARIF files as evidence for the
  one rule named with `--rule`; any finding makes it `open`, none leaves it alone.
- Both formats are `.json`, like HDF, so a `.json` file is identified by its content: `runs`
  and `version` (SARIF), `profiles` (HDF), `auditReportVersion` (npm audit), or a
  `dependencies` list with `fixes` (pip-audit). Anything else is refused by name. `.sarif`
  files are still taken as SARIF by name, and SARIF saved as `.json` is now found by content.
- pip-audit: one finding per package, version and vulnerability id; repeats are merged and
  counted as `duplicate`. The level is `unrated`, since pip-audit gives none. The message is
  `requests 2.19.1 (CVE-..., GHSA-...); fixed in 2.20.0`; descriptions are left out to keep
  the summary readable, and the ids lead to them. Unaudited packages are named in the summary.
- npm audit: one finding per package and advisory (the GHSA id, else `npm-advisory-<source>`),
  merging repeats and keeping the most severe. Levels are npm's own words, which the summary
  orders across tools: critical, high, error, moderate, warning, low, note, info, none,
  unrated. Packages affected only through others are named in the summary. Report version 1
  (npm 6 and earlier) is refused by name.
- The input pins are recorded in NOTICE, not committed as `requirements.txt` or
  `package.json`: dependency scanners read those anywhere in a repository and would raise
  alerts on pins that are vulnerable on purpose.

## How decisions 4-6 apply to a scan

A scan's review is its status and finding details only, since decision 5 keeps it away from
comments and overrides. For each matched rule:

- The checklist rule is `not_reviewed` with no finding details: the scan's review is applied.
- The checklist rule already has the scan's status: unchanged.
- Otherwise it is a conflict: a different status, or a `not_reviewed` rule whose finding details
  the scan would replace. The checklist wins unless `--prefer results`.

Release identity, from each STIG's `version` and `release_info`, first form that applies:

1. `version` like `V2R5` -> (2, 5).
2. `version` like `002.010` or `6.3.3` -> (2, 10) or (6, 3).
3. "Release: N" in the release info -> (version, N) when `version` is a plain number, otherwise
   (unknown, N).

Releases must agree, and versions too where both sides know theirs. The unknown-version case is
common: schema-valid CKLB, which STIG Viewer 3 and stigforage write, has no STIG-level `version`,
so a checklist like the Chrome fixture is known only as "Release: 8". Comparing the release alone
still catches that fixture against an Evaluate-STIG scan of V2R9. When either side has no
recognisable identity at all, the release cannot be compared: that is a warning, not a refusal.

Host match: the checklist's host name, compared case-insensitively on the part before the first
dot, must equal the scan's `target` or its `host_name` or `fqdn` fact. A blank checklist host
(for example a checklist made from a benchmark) never refuses.
