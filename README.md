# stigforage

Free, offline STIG checklist toolkit. Working name. Donationware: free to use, no feature gating,
no nag screens, no network access.

**Status: pre-release (V0.2.2 accepted).** Not yet usable as a replacement
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
- `stigforage convert INPUT -o OUTPUT` converts between `.cklb`, `.ckl` and benchmarks. It is a
  dry run unless you pass `--apply`, never modifies INPUT, and refuses to overwrite OUTPUT without
  `--force`. A dry run reports the same refusals and export warnings as `--apply` would.

Exit codes: 0 ok, 1 validation errors, 2 a file could not be read, parsed or written, or the
operation was refused (for example OUTPUT would overwrite an input, or `merge` was given two
different releases).

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
stigforage --help
stigforage convert U_RHEL_9_STIG_V1R1_Manual-xccdf.xml -o rhel9.cklb          # dry run
stigforage convert U_RHEL_9_STIG_V1R1_Manual-xccdf.xml -o rhel9.cklb --apply  # write it
pytest
```

Requires Python 3.11+. The only runtime dependency is `structlog`; XML is parsed with a hardened
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
- The SCAP data stream path is tested only with a synthetic wrapper around a real benchmark.
- Defaults such as `active`/`mode`/`has_path` and `reference_identifier` come from public
  fixtures, not from DISA documentation.

## Roadmap

- **V0.1.1** (accepted): core model, CKLB I/O, CKL and XCCDF/SCAP import, `convert` CLI.
- **V0.2.2** (accepted): carry-forward merge, STIG upgrade wizard, checklist diff.
- **V0.3.3** (planned): result importers: SCC/XCCDF/ARF, InSpec HDF, SARIF, pip-audit/npm
  audit/CVE JSON.
- **V0.4.4** (planned): CSV, POA&M and evidence ZIP export; CCI to NIST 800-53 Rev 5 crosswalk;
  dashboard data.
- **V0.5.5** (planned): refactor and stabilization.
- **V1.x** (planned): PySide6 desktop GUI, packaging for Windows, Linux, macOS.

## Principles

- Offline by default. No telemetry, no update checks, no CDN assets.
- Never modifies input files. State-changing commands are dry-run unless `--apply` is given.
- No DISA content is bundled. You import STIGs you downloaded from DoD Cyber Exchange.

## Disclaimer

Not affiliated with or endorsed by DISA or the U.S. Department of Defense. "STIG" is used
descriptively.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Test fixtures are MIT-licensed
third-party material; see NOTICE.
