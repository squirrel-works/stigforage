# ADR 0001: Core architecture (V0.1.1)

Status: accepted by maintainer (all seven points confirmed).

1. Layout: `src/stigforage/` with `model.py`, `cklb.py`, `log.py`, `cli.py`; `ckl.py` and `xccdf.py` follow in V0.1.1 checkpoint 2.
2. Model: typed dataclasses mirroring CKLB. Unmodelled keys live in `extra` and round-trip verbatim.
3. Persistence: no database. CKLB JSON is the only persisted state. Atomic writes, source never modified, no overwrite without `--force`.
4. Dry-run: state-mutating commands (`convert`, later others) default to dry-run and need `--apply`.
5. Validation: structural checks derived from fixtures. `--schema PATH` for the DISA CKLB JSON Schema is added when the schema is supplied; `jsonschema` is deliberately not a dependency yet.
6. Dependencies: runtime `structlog` (+ `defusedxml` when XML lands); dev `pytest`, `ruff`, `black`, `mypy --strict`.
7. Input safety: ZIPs read in memory with size and entry caps, nothing extracted to disk; XML via `defusedxml`.

## Evidence-driven corrections during implementation

- STIG `version` is a string in 20 of 25 public fixtures and an int in 5; the type is preserved as read.
- Duplicate `group_id` within a STIG is a validation warning, not an error: public fixtures contain duplicates.
- Top-level `evaluate-stig` / `cklb_version` keys confirm that `extra` preservation is required, not speculative.
