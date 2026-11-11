# ADR 0005: Exports and the CCI to 800-53 Rev 5 crosswalk (V0.4.4)

Status: decisions 1-10 accepted by maintainer (2026-11-11).

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
  and "Source Identifying Vulnerability " with a trailing space).
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
6. POA&M: STIG Manager's 26-column eMASS layout, unverified against an eMASS instance. One row
   per open rule across all input checklists, Controls / APs from the crosswalk when given,
   CCIs in Comments, and `--office`, `--completion-date` and `--poam-status` (default
   `Ongoing`) for the assessor's fields. `not_reviewed` rules are counted, not listed.
7. `.xlsx` is written by a small stdlib writer (zipfile and XML), with no new runtime
   dependency. Tests read it back structurally; whether openpyxl joins as a pinned dev-only
   cross-check is decided in that unit.
8. Dashboard data: a JSON document with `"schema_version": 1`, documented in `docs/`, for the
   V1.x GUI and outside dashboards. Per host and per STIG: counts by status and CAT, percent
   reviewed, open CAT I. With `--cci-list`, also status by Rev 5 family and control.
9. Evidence ZIP: the input checklists as CKLB, the CSV, the POA&M and the dashboard JSON, plus
   `manifest.json` with each file's SHA-256, the input file names and hashes, the stigforage
   version and the creation time. `--include FILE` adds raw evidence such as scan outputs.
10. Fixtures: no CCI list is committed (decision 1); the POA&M headers as constants in code,
    credited to STIG Manager in NOTICE.

## Units

1. CCI crosswalk (library; the exports expose it).
2. CSV export.
3. POA&M export.
4. Dashboard data.
5. Evidence ZIP.
