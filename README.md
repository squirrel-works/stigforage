# stigforage

Free, offline STIG checklist toolkit. Working name. Donationware: free to use, no feature gating, no nag screens, no network access.

**Status: pre-release (V0.1.1, in progress).** Not yet usable as a replacement for anything. The roadmap below shows what exists and what does not.

## What works today

- Read and write DISA STIG Viewer 3 `.cklb` checklists with lossless round trips (unknown keys are preserved).
- `stigforage info FILE...` summarises hosts, STIGs, rule counts, severity and review status.
- `stigforage validate FILE... [--strict]` checks structural problems. Exit codes: 0 ok, 1 validation errors, 2 unreadable file.

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
stigforage --help
pytest
```

Requires Python 3.11+.

## Roadmap

| Stage | Scope | State |
|---|---|---|
| V0.1.1 | Core model, CKLB I/O, CKL and XCCDF/SCAP import, `convert` CLI | CKLB I/O done; CKL, XCCDF, `convert` pending |
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
