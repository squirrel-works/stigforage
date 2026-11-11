# ADR 0005: Exports and the CCI to 800-53 Rev 5 crosswalk (V0.4.4)

Status: decisions 1-10 accepted by maintainer (2026-11-11). Decisions 6 and 7, and decision
10's POA&M headers, were superseded the same day by the unit 3 revision below, when current
eMASS templates turned up.

## Evidence

- DISA's `U_CCI_List.zip` (version 2025-01-23, the latest published) is a public download at
  `dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip`. Its `U_CCI_List.xml` (root
  `cci_list`, namespace `http://iase.disa.mil/cci`) holds 5,137 CCIs, 91 deprecated. 3,836 map to
  "NIST SP 800-53 Revision 5" (3,838 references; a few CCIs map to two); the other 1,301 have
  only Revision 3 or 4 references.
- On real data, 853 of RHEL 9 V2R10's 923 CCI references (92%) have a Rev 5 mapping, across 47
  controls; the rest point at CCIs with no Rev 5 entry (for example `CCI-002132`). No fixture
  uses a CCI missing from the list or a deprecated one.
- Every Rev 5 reference is a control, an optional enhancement in parentheses, then parts:
  `AC-2`, `AC-2 (4)`, `AC-2 e`, `AC-1 c 1`, `AC-2 (3) (d)`, `IA-5 (2) (b) (1)`. DISA also writes
  some parts of a base control in parentheses (`CP-9 (a)`): a parenthesised number is an
  enhancement, a parenthesised letter a part. Two deprecated CCIs still have Rev 5 references.
- eMASS imports its own `.xlsx` POA&M template, which is behind a DoD login, and the maintainer
  has none. STIG Manager (MIT) ships an eMASS layout (`api/source/utils/poam-template.xlsx`): 26
  columns, POA&M Item ID through Resulting Residual Risk after Proposed Mitigations. It writes
  one row per open finding grouped across assets, Raw Severity as CAT I/II/III, Severity as
  Low/Moderate/High, and takes Office/Org, the completion date and the status as defaults. Two
  headers look Navy-specific ("Mitigations (in-house and in conjunction with the Navy CSSP)",
  and "Source Identifying Vulnerability " with a trailing space). This turned out to be an
  older layout; the unit 3 revision records the current templates.
- No established findings-CSV format exists to follow: STIG Manager's CSV files are asset
  inventories.
- openpyxl 3.1.5 is MIT, pure Python, with one dependency, but its last release was June 2024,
  about 29 months before this stage: the "actively maintained" concern that ruled out
  defusedxml (ADR 0001).

## Decisions

1. The crosswalk reads DISA's CCI list from a file the user supplies (`--cci-list`, `.zip` or
   `.xml`), so nothing from DISA ships with the tool. Nothing from the CCI list is committed
   either (maintainer's decision): for local runs, DISA's real `U_CCI_List.zip` is downloaded to
   `tests/fixtures/local/`, which is gitignored, and the tests that need it skip with the
   download command when it is absent, as in CI. The crosswalk's rules are tested everywhere
   against a small synthetic list built in the tests. Without `--cci-list`, control columns stay
   empty and the output says why.
2. Both granularities: DISA's reference as written (`CM-6 b`) and the control it belongs to.
   The control is written in NIST's form, an enhancement included: `AC-2 (3) (d)` belongs to
   `AC-2(3)`, `CP-9 (a)` to `CP-9`. The POA&M and the dashboard roll up by control and family.
3. A CCI with no Rev 5 reference is reported as unmapped, never filled in from Revision 4 or
   guessed. A deprecated CCI still maps if it has a Rev 5 reference, but is flagged.
4. One command: `export {csv,poam,dashboard,evidence} CHECKLIST... -o OUTPUT [--cci-list
   PATH]`. Several checklists (one per host) are allowed. Dry run unless `--apply`, like every
   command that writes.
5. CSV: one row per rule, per STIG, per checklist, with host, STIG id, release, V-number, rule
   id, STIG rule id, severity, CAT, status, title, comments, finding details, CCIs, and Rev 5
   controls when `--cci-list` is given. UTF-8 with a byte-order mark, so Excel opens it
   correctly. A cell starting with `=`, `+`, `-` or `@` gets a leading apostrophe, because
   finding details from scans are untrusted and Excel would run them as formulas.
6. (Superseded by the unit 3 revision.) POA&M: STIG Manager's 26-column eMASS layout,
   unverified against an eMASS instance. One row per open rule across all input checklists,
   Controls / APs from the crosswalk when given, CCIs in Comments, and `--office`,
   `--completion-date` and `--poam-status` (default `Ongoing`) for the assessor's fields.
   `not_reviewed` rules are counted, not listed.
7. (Superseded by the unit 3 revision.) `.xlsx` is written by a small stdlib writer (zipfile
   and XML), with no new runtime dependency. Tests read it back structurally, and openpyxl
   3.1.5 joins as a pinned dev-only cross-check so CI runs it too (decided in unit 3,
   maintainer-approved).
8. Dashboard data: a JSON document with `"schema_version": 1`, documented in `docs/`, for the
   V1.x GUI and outside dashboards. Per host and per STIG: counts by status and CAT, percent
   reviewed, open CAT I. With `--cci-list`, also status by Rev 5 family and control.
9. Evidence ZIP: the input checklists as CKLB, the CSV, the POA&M and the dashboard JSON, plus
   `manifest.json` with each file's SHA-256, the input file names and hashes, the stigforage
   version and the creation time. `--include FILE` adds raw evidence such as scan outputs.
10. Fixtures: no CCI list is committed (decision 1); the POA&M headers as constants in code,
    credited to STIG Manager in NOTICE. (The POA&M headers part is superseded by the unit 3
    revision: no layout ships, and the eMASS templates are local-only test data.)

## Unit 2: CSV (details within decision 5, maintainer-approved after review, 2026-11-11)

- `finding_rows` is the flattening every export shares: one row per rule, per STIG, per
  checklist, in input order. The POA&M and the dashboard build on it.
- Columns, with STIG Viewer's labels where one exists: Host, STIG, Release, Vuln ID, Rule ID,
  STIG ID, Severity, CAT, Status, Rule Title, Comments, Finding Details, CCIs, NIST 800-53 Rev 5
  Controls, NIST 800-53 Rev 5 References, Rev 5 Crosswalk Notes. The set is fixed: without
  `--cci-list` the last three stay empty, so a spreadsheet built on the export keeps its shape.
- Status is written as words (`Not a Finding`). CAT is I/II/III from the severity, empty for
  `unknown`. Release is `V2R10`, `V?R10` when only the release is known (schema-valid CKLB has
  no STIG version), else the release info as written.
- Lists in one cell (CCIs, controls, references, notes) are joined with a semicolon and a
  space. A CCI listed twice by a rule appears once.
- The notes name each CCI that does not map cleanly: `CCI-002132: no Rev 5 reference`,
  `not in the CCI list`, or `deprecated`. The command also prints a crosswalk summary (CCI
  references mapped, and counts of each problem), or says that no `--cci-list` was given.
- CRLF line endings, as CSV for Excel expects. Formula neutralising covers OWASP's list: `=`,
  `+`, `-`, `@`, tab and carriage return. Values such as `-2` gain an apostrophe too; the export
  has no numeric columns, so nothing is lost.
- The output must end in `.csv`, may not be an input (the CCI list included), and follows the
  dry-run and `--force` rules of every other command that writes.

## Unit 3: POA&M

The first design (decisions 6 and 7, maintainer-approved after review, 2026-11-11) wrote STIG
Manager's 26-column layout into a workbook of stigforage's own. It was superseded the same day,
before it was committed, by the revision below. A late change in it, dropping the trailing space
from STIG Manager's "Source Identifying Vulnerability " header, went with it.

### Revision: fill the user's own eMASS template (maintainer-approved, 2026-11-11)

Evidence:

- Current eMASS POA&M templates are public after all. NSWC Crane's C-PAT publishes the Navy,
  Army and Marine Corps ones (`NSWC-Crane/C-PAT`, `client/src/assets/`; the Navy one was updated
  there on 2026-06-01). Each has a CUI banner in rows 1-6, headers in row 7 from column B,
  entries from row 8, and Example and Instructions sheets. Navy has 32 columns, Marine Corps 31
  (Navy's without the last), Army 40 (no Predisposing Conditions or Threat Description, plus
  CFO-audit and resource columns).
- STIG Manager's template (headers in row 1, one Status, milestones in one cell) is an older
  layout. An export in it would almost certainly not import.
- The templates' instructions: several controls or security checks are separated by semicolons.
  Raw Severity, Severity and the risk columns take Very Low to Very High. An Ongoing item needs
  at least one milestone (description, status and scheduled date); a Risk Accepted item may have
  none. Both need Office/Org, Resources Required and Identification Source. The Army and Marine
  Corps instructions add that Identification Source takes values from a glossary sheet, which
  none of the copies holds.
- The instructions warn that deleting columns, sheets or the classification label "may have a
  negative impact on the ability for eMASS to ingest the template". eMASS likely reads by
  position, and the positions differ by branch.
- Header text varies: Army heads a column "Identification Source " (a trailing space) and
  others with line breaks.
- C-PAT's license is its own and restrictive (derivative works must be open source and
  delivered to NSWC Crane; no sale without consent), so its template files are not
  redistributed. They are downloaded to `tests/fixtures/local/emass/` (gitignored), and the
  tests that use them skip with the download command when they are absent, as in CI.

Superseded decisions and their replacements:

- Decision 6 and decision 10's POA&M headers: `export poam --template XLSX` fills a copy of the
  blank POA&M import template the user exports from eMASS; the template itself is never
  modified. Without `--template`, `export poam` is refused. No layout ships with stigforage:
  like the CCI list, the reference material is the user's.
- Decision 7: the stdlib writer becomes a stdlib template filler. openpyxl stays a pinned
  dev-only cross-check.
- The trailing-space question is moot: headers are matched normalised, so each branch's
  spacing works.
- Identification Source: first proposed as the STIG and its release, as C-PAT writes it. Given
  the glossary instruction, those go in Identification Source Details instead, and
  Identification Source is left for the assessor (a call the maintainer delegated).

The filler (`xlsx.py`, standard library only):

- It finds the sheet named `POA&M`, takes the first row holding "Control Vulnerability
  Description" as the header row, and finds each column by its header after collapsing
  whitespace (line breaks included) and folding case. A field that is missing, or headed twice,
  is refused by name.
- It refuses what it cannot fill safely: a file that is not a ZIP (a password-protected
  workbook included), a macro-enabled workbook, an Excel template file (`.xltx`), and a sheet
  with entries below its header. Formatting-only rows below the header make way for the new
  rows or stay below them.
- Only the worksheet changes (its new rows and its used range), plus the stylesheet when a date
  column has no date format: that column's cell format is copied with Excel's short date
  (built-in format 14). Every other part is kept byte for byte. The XML is edited as text, not
  re-serialised, because ElementTree renames namespace prefixes and drops declarations that
  only `mc:Ignorable` names, which Excel then reports as corrupt. Each edit is parsed again
  before it is accepted.
- New text cells are inline strings in the column's style, so nothing is evaluated as a formula
  and the shared-string table is untouched. Dates are serial numbers; a date before 1900-03-01,
  where Excel's serials are off by one, is refused. XML-illegal characters are removed, a cell
  over 32,767 characters is truncated with a marker, and ZIP entries carry a fixed timestamp,
  so the same template and rows give the same bytes (the evidence ZIP hashes them).

The POA&M (`exports.poam_items`):

- One item per open rule, grouped by STIG and V-number across every checklist, CAT I first,
  then STIG id, then V-number in numeric order: unchanged from the first design.
- Filled: Control Vulnerability Description (`Title:` and the rule title, then `Description:`
  and its discussion), Controls / APs (the Rev 5 controls), Security Checks (rule ids), POA&M
  Status, Identification Source Details (STIG id, release and release info, one block per
  distinct release), Office/Org, Comments (the CCIs, then any crosswalk notes), Raw Severity
  and Severity (High, Moderate or Low from CAT I, II or III), and Devices Affected (one host
  per line). Controls and security checks are separated by semicolons.
- Left for the assessor: Identification Source, Resources Required, mitigations, predisposing
  conditions and the risk analysis (relevance of threat, likelihood, impact, residual risk).
  The first design copied the severity into the residual-risk columns; the instructions call
  Residual Risk Level calculated, so it is no longer filled. POA&M Item ID and Milestone ID
  stay blank for eMASS to assign.
- `--poam-status` is `Ongoing` (the default) or `Risk Accepted`. An Ongoing item gets one
  milestone: "Resolve this finding.", status `Open` (the values C-PAT offers are Open, In
  Progress, Delayed, Completed and Archived; the templates' own lists are broken references in
  every copy), and `--completion-date` as both its date and the item's Scheduled Completion
  Date. A Risk Accepted item gets no milestone, and `--completion-date` is refused with it.
- The command warns about each field eMASS requires that the export leaves empty, with the
  number of items affected. It never refuses over them: assessors finish the sheet in Excel.
  Resources Required and Identification Source are always reported.
- Rules not reviewed are counted in the command's output, not listed.

Verification:

- All three real templates were filled from the two multi-STIG fixtures. openpyxl reads each
  value in the column its header names, and dates as dates; rows 1-7 are unchanged; every
  other part is byte-identical, apart from Navy's stylesheet, which gains one date format. The
  suite holds this as a local-only test.
- The output has not been opened in Excel or imported into eMASS: both remain unverified.

## Units

1. CCI crosswalk (library; the exports expose it).
2. CSV export.
3. POA&M export.
4. Dashboard data.
5. Evidence ZIP.
