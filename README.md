# stigforage

Free, offline STIG checklist toolkit. Working name. Donationware: free to use, no feature gating,
no nag screens, no network access.

**Status: pre-release (V0.3.3 accepted).** Not yet usable as a replacement
for anything. The roadmap below shows what exists and what does not.

> CKLB output is checked against the DISA schema, not against STIG Viewer 3 itself (which has no
> macOS build, so it has not been possible to test there).

## What works today

- Read and write DISA STIG Viewer 3 `.cklb` checklists with lossless round trips (unknown keys
  are preserved).
- Read and write legacy `.ckl` checklists. The writer mirrors the layout of the public STIG
  Manager CKL files and is **not yet tested against STIG Viewer 2.x or eMASS**.
- Turn an XCCDF benchmark, a SCAP data stream, or a ZIP of either into a blank `.cklb` checklist.
- `stigforage info FILE...` summarises hosts, STIGs, rule counts, severity and review status.
- `stigforage validate FILE... [--strict]` checks structural problems.
- `stigforage diff OLD NEW` compares two checklists or benchmarks rule by rule (read-only). Rules
  are matched by `rule_id_src`, then by unambiguous `group_id`; see
  `docs/adr/0002-matching-merge-upgrade-policy.md`.
- `stigforage merge SOURCE TARGET -o OUTPUT` carries reviews (status, comments, finding details,
  overrides) from SOURCE into a copy of TARGET for the same STIG release. Rules with no review
  in TARGET receive SOURCE's; differing reviews are listed as conflicts and TARGET wins unless
  `--prefer source`. Dry run unless `--apply`, like `convert`.
- `stigforage upgrade OLD NEW_BENCHMARK -o OUTPUT` carries OLD's reviews onto a new release of
  its STIGs. A rule whose check text changed is reset to `not_reviewed` with a note in its
  comments, unless `--keep-status-on-change`. The report lists added rules, removed rules whose
  review is lost, and severity changes. Dry run unless `--apply`. The test suite uses synthetic
  releases built from the public fixtures; one real release step (RHEL 9 V2R9 to V2R10) was
  checked by hand, see ADR 0002.
- `stigforage import-results CHECKLIST RESULTS... -o OUTPUT` applies scan results (SCC,
  Evaluate-STIG, OpenSCAP or STIG Manager XCCDF results, ARF, or InSpec HDF `.json`) to the
  STIGs they scanned.
  `pass`, `fail` and `notapplicable` set the status and finding details; other results are
  counted, not imported; comments are never touched. The checklist wins conflicts unless
  `--prefer results`. Scans of another release are refused, and so are scans of another host
  unless `--allow-host-mismatch`. SARIF (from Trivy, Grype, OSV-Scanner, Flawfinder and
  others) and pip-audit or npm audit JSON name no STIG rule, so `--rule V-NUMBER` says which
  rule they are evidence for: any finding makes it `open`, and no findings leave it alone.
  `.json` files are identified by their content. Dry run unless `--apply`. See ADR 0003.
- `stigforage convert INPUT -o OUTPUT` converts between `.cklb`, `.ckl` and benchmarks. It is a
  dry run unless you pass `--apply`, never modifies INPUT, and refuses to overwrite OUTPUT without
  `--force`. A dry run reports the same refusals and export warnings as `--apply` would.

Exit codes: 0 ok, 1 validation errors, 2 a file could not be read, parsed or written, or the
operation was refused (for example OUTPUT would overwrite an input, or `merge` was given two
different releases).

```sh
python3.14 -m venv .venv && . .venv/bin/activate   # Windows: py -3.14 -m venv .venv
pip install -e ".[dev]"                             # dev tools are pinned; see ADR 0004
stigforage --help
stigforage convert U_RHEL_9_STIG_V1R1_Manual-xccdf.xml -o rhel9.cklb          # dry run
stigforage convert U_RHEL_9_STIG_V1R1_Manual-xccdf.xml -o rhel9.cklb --apply  # write it
pytest
```

Requires Python 3.14+. The only runtime dependency is `structlog`; XML is parsed with a hardened
standard-library parser that rejects any DTD or entity declaration.

## Known gaps in V0.1.1

- `validate --schema PATH` checks against the DISA CKLB schema, but the bundled validator
  supports only the keywords that schema uses; any other keyword is a loud error, not a silent
  pass.
- Every public CKLB fixture (all produced by STIG Manager or Evaluate-STIG) fails the DISA schema;
  `validate --schema` reports that rather than hiding it. Our own output validates.
- CKL -> CKLB drops the STIG `version` number (the schema has no key for it; it remains in
  `stig_ref`/`release_info`).
- CKL severity overrides and non-default `MARKING` values are reported as warnings but not carried
  to CKLB, and CKLB rule overrides are not written to CKL: the CKLB layout for them is unverified.
- The SCAP data stream path is tested in the suite only with a synthetic wrapper around a real
  benchmark. A real DISA SCAP 1.3 data stream (RHEL 9 V2R10) was loaded by hand during V0.3.3;
  see ADR 0003.
- Defaults such as `active`/`mode`/`has_path` and `reference_identifier` come from public
  fixtures, not from DISA documentation.

## Known gaps in V0.3.3

- The only real ARF tested is OpenSCAP's. SCC's own ARF is untested: SCC needs a DoD login to
  download.
- No real HDF sample has waiver data, so waived controls (counted, never imported) are tested on
  synthetic files only. HDF attestations are not read.
- SARIF and dependency audits record no release or host, so neither can be checked; each import
  says so in a warning. pip-audit reports no severity, so its findings are `unrated`.
- Scans are imported, not judged: whether a passing scan is enough evidence for a rule is still
  the assessor's call, and `import-results` never touches comments.

## Roadmap

| Stage | Scope | State |
| --- | --- | --- |
| V0.1.1 | Core model, CKLB I/O, CKL and XCCDF/SCAP import, `convert` CLI | accepted |
| V0.2.2 | Carry-forward merge, STIG upgrade wizard, checklist diff | accepted |
| V0.3.3 | Importers: SCC/XCCDF/ARF, InSpec HDF, SARIF, pip-audit, npm audit | accepted |
| V0.4.4 | CSV/POA&M/evidence ZIP export, CCI to 800-53 Rev 5 crosswalk, dashboard data | planned |
| V0.5.5 | Refactor and stabilization | planned |
| V1.x | PySide6 desktop GUI, packaging for Windows, Linux, macOS | planned |

V0.3.3's SARIF importer also covers Trivy, Grype and OSV-Scanner, which all write SARIF.

## Principles

- Offline by default. No telemetry, no update checks, no CDN assets.
- Never modifies input files. State-changing commands are dry-run unless `--apply` is given.
- No DISA content is bundled with the tool. You import STIGs you downloaded from DoD Cyber
  Exchange. (The test fixtures hold truncated excerpts; see NOTICE.)

## Disclaimer

Not affiliated with or endorsed by DISA or the U.S. Department of Defense. "STIG" is used
descriptively.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Test fixtures include
third-party material under the MIT and Apache 2.0 licenses, advisory text under CC BY 4.0, and
truncated DISA content; NOTICE lists each source.
