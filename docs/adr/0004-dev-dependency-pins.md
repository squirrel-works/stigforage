# ADR 0004: Pinned dev tools and a project .venv (during V0.3.3)

Status: accepted by maintainer (2026-11-10).

## Context

- The dev tools were unpinned (`ruff`, `black`, `mypy`, `pytest>=8`), so CI installed the newest
  release on every run. A new ruff, black or mypy release could fail CI with no code change.
- Development ran from a temporary virtual environment outside the repository, so VS Code had no
  project interpreter and showed diagnostics that mypy does not.
- `tests/test_schema.py` cross-checks `schema.py` against `jsonschema` through
  `pytest.importorskip`, but `jsonschema` was not a dev dependency. CI never installed it, so the
  cross-check ADR 0001 describes was always skipped there.
- Installing from `pyproject.toml` warned that `license = { text = "Apache-2.0" }` is deprecated
  and that builds using it stop working after 2027-02-18.

## Decision

1. A local `.venv` at the repository root (Python 3.14), gitignored, built with
   `python3.14 -m venv .venv && .venv/bin/pip install -e ".[dev]"`. markdownlint already skips
   gitignored paths.
2. Exact pins for the direct dev tools in the `dev` extra: `pytest==9.2.0`, `ruff==0.17.4`,
   `black==26.10.1`, `mypy==2.4.1`, plus `jsonschema==4.26.0` so CI runs the schema
   cross-check. These are the versions the `.venv` resolved on 2026-11-10. `jsonschema` stays
   out of the runtime dependencies (ADR 0001 point 5); `importorskip` remains, so the suite
   still runs without it.
   Added during V0.4.4 (ADR 0005 decision 7, maintainer-approved): `openpyxl==3.1.5`, which
   cross-checks the stdlib `.xlsx` template filler in the same way and is never a runtime
   dependency.
   Its last release is from June 2024; that matters less for a test-only reader, and the
   test skips if it cannot be imported.
3. Pins change deliberately: at the start of a roadmap stage, in their own commit, with the full
   suite run.
4. The runtime dependency stays a range (`structlog>=24.1`): stigforage is also installable as a
   library, and an exact runtime pin would conflict with other packages in the same environment.
5. `license = "Apache-2.0"` (an SPDX expression), with `setuptools>=77` in `[build-system]`, which
   that form needs. The built wheel carries `License-Expression: Apache-2.0` and ships LICENSE
   and NOTICE.

This extends ADR 0001 point 6 (dev dependencies) with `jsonschema` and the pins.

## Deferred

A fully locked, hashed requirements file (pip-tools `pip-compile --generate-hashes`, installed
with `--require-hashes`) would pin every transitive dependency for all three platforms and serve
as the list for an offline wheel cache. It adds a tool and a regenerate step, so it waits for
V1.x packaging, which needs a reproducible offline build anyway. Until then the tools' own
dependencies (click, pathspec, pluggy, rpds-py and others) float.

## Evidence

- `rpds-py`, which `jsonschema` needs, publishes Python 3.14 wheels for Linux x86_64, Windows
  x64 and macOS arm64, so CI needs no Rust compiler.
- After the change, the full suite runs with no skips (449 passed), and installing raises no
  deprecation warning.
