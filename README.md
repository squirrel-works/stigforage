# stigforage

Free, offline STIG checklist toolkit. Working name. Donationware: free to use, no feature gating, no nag screens, no network access.

**Status: pre-release (V0.1.1, in progress).** Not yet usable as a replacement for anything. The roadmap below shows what exists and what does not.

## What works today

- Read and write DISA STIG Viewer 3 `.cklb` checklists with lossless round trips (unknown keys are preserved).
- Read and write legacy `.ckl` checklists. The writer mirrors the layout of the public STIG Manager CKL files and is **not yet tested against STIG Viewer 2.x or eMASS**.
- Turn an XCCDF benchmark, a SCAP data stream, or a ZIP of either into a blank `.cklb` checklist.
- `stigforage info FILE...` summarises hosts, STIGs, rule counts, severity and review status.
- `stigforage validate FILE... [--strict]` checks structural problems.
- `stigforage convert INPUT -o OUTPUT` converts between `.cklb`, `.ckl` and benchmarks. It is a dry run unless you pass `--apply`, never modifies INPUT, and refuses to overwrite OUTPUT without `--force`.

Exit codes: 0 ok, 1 validation errors, 2 a file could not be read, parsed or written.

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
stigforage --help
stigforage convert U_RHEL_9_STIG_V1R1_Manual-xccdf.xml -o rhel9.cklb          # dry run
stigforage convert U_RHEL_9_STIG_V1R1_Manual-xccdf.xml -o rhel9.cklb --apply  # write it
pytest
```

Requires Python 3.11+. The only runtime dependency is `structlog`; XML is parsed with a hardened standard-library parser that rejects any DTD or entity declaration.

## Known gaps in V0.1.1

- `validate --schema PATH` checks against the DISA CKLB schema, but the bundled validator supports only the keywords that schema uses; any other keyword is a loud error, not a silent pass.
- Every public CKLB fixture (all produced by STIG Manager or Evaluate-STIG) fails the DISA schema; `validate --schema` reports that rather than hiding it. Our own output validates.
- CKL -> CKLB drops the STIG `version` number (the schema has no key for it; it remains in `stig_ref`/`release_info`).
- Severity overrides and non-default CKL markings are dropped with a warning: the CKLB override layout is unverified.
- CKL severity overrides and `MARKING` are reported as warnings but not carried to CKLB: the CKLB layout for them is unverified.
- The SCAP data stream path is tested only with a synthetic wrapper around a real benchmark.
- Defaults such as `active`/`mode`/`has_path` and `reference_identifier` come from public fixtures, not from DISA documentation.

## Roadmap

| Stage | Scope | State |
|---|---|---|
| V0.1.1 | Core model, CKLB I/O, CKL and XCCDF/SCAP import, `convert` CLI | implemented incl. `--schema`; complete but NOT yet accepted |
| V0.2.2 | Carry-forward merge, STIG upgrade wizard, checklist diff | planned |
| V0.3.3 | Result importers: SCC/XCCDF/ARF, InSpec HDF, SARIF, pip-audit/npm audit/CVE JSON | planned |
| V0.4.4 | CSV, POA&M and evidence ZIP export; CCI to NIST 800-53 Rev 5 crosswalk; dashboard data | planned |
| V0.5.5 | Refactor and stabilization | planned |
| V1.x | PySide6 desktop GUI, packaging for Windows, Linux, macOS | planned |

## Principles

- Offline by default. No telemetry, no update checks, no CDN assets.
- Never modifies input files. State-changing commands are dry-run unless `--apply` is given.
- No DISA content is bundled. You import STIGs you downloaded from DoD Cyber Exchange.

## Disclaimer

Not affiliated with or endorsed by DISA or the U.S. Department of Defense. "STIG" is used descriptively.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Test fixtures are MIT-licensed third-party material; see NOTICE.
