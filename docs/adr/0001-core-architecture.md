# ADR 0001: Core architecture (V0.1.1)

Status: accepted by maintainer (all seven points confirmed).

1. Layout: `src/stigforage/` with `model.py`, `cklb.py`, `ckl.py`, `xccdf.py`, `xmlsafe.py`, `fsio.py`, `log.py`, `cli.py`.
2. Model: typed dataclasses mirroring CKLB. Unmodelled keys live in `extra` and round-trip verbatim.
3. Persistence: no database. CKLB JSON is the only persisted state. Atomic writes, source never modified, no overwrite without `--force`.
4. Dry-run: state-mutating commands (`convert`, later others) default to dry-run and need `--apply`.
5. Validation: structural checks plus `validate --schema PATH` against the DISA CKLB JSON Schema via `schema.py`, a stdlib subset validator. `jsonschema` is not a dependency (it pulls in `rpds-py`, a compiled Rust extension); `schema.py` raises `SchemaError` on any keyword it does not implement, and tests cross-check it against `jsonschema` (optional, via `importorskip`) on all fixtures.
6. Dependencies: runtime `structlog` only; dev `pytest`, `ruff`, `black`, `mypy --strict`.
7. Input safety: ZIPs read in memory with size and entry caps, nothing extracted to disk; XML via `xmlsafe.py` (see below).

## Evidence-driven corrections during implementation

- STIG `version` is a string in 20 of 25 public fixtures and an int in 5; the type is preserved as read.
- Duplicate `group_id` within a STIG is a validation warning, not an error: public fixtures contain duplicates.
- Top-level `evaluate-stig` / `cklb_version` keys confirm that `extra` preservation is required, not speculative.

## Findings from the DISA schema (SV3_CKLB_1_0_JSON_SCHEMA.json, draft 2019-09)

- Top level and `target_data` are closed (`additionalProperties: false`); only `title` and `id` are required. `stigs` and `rules` are optional.
- `stig` has no `version` key. Rule text fields must be strings (never null); only `target_key`, `stig_ref`, `reference_identifier`, `check_content`, `check_content_ref` may be null.
- `severity` allows `unknown`; `cklb_version` is const "1.0"; `STIGUuid` is deprecated.
- Consequence: STIG Manager and Evaluate-STIG output does not validate. `Stig.write_version` records whether the source had `version`, so raw CKLB round-trips verbatim while generated CKLB omits it.
- Generated `rule_id` strips the `xccdf_mil.disa.stig_rule_`/`_rule` decoration; `reference_identifier` is the real `dc:identifier` (replacing the fixture placeholder "0000").

## Decision: stdlib XML parsing, not defusedxml (maintainer decision)

`defusedxml`'s latest release is 0.7.1, which fails the project's "actively maintained" criterion.
`xmlsafe.py` drives `xml.parsers.expat` directly and refuses any DTD, entity or notation
declaration through expat's own callbacks. That also holds for UTF-16 input, which a byte-level
scan for `<!DOCTYPE` would miss. Nesting depth is capped. STIG, XCCDF and CKL files never need a DTD.

## Known unverified assumptions

- Defaults copied from public fixtures, not from DISA documentation: `active=false`, `mode=1`, `has_path=true`, target_data keys, `check_content_ref.name="M"`, `classification="NONE"`, blank-checklist `target_type="Computing"`.
- CKL layout is modelled on STIG Manager's output; not tested with STIG Viewer 2.x or eMASS.
- SCAP data stream support rests on the SCAP 1.2 source data stream layout, tested only with a synthetic wrapper.
- CKLB severity-override layout: the schema says `overrides` is an object keyed by `^[a-zA-Z_]+$` with a `reason` string plus string values, but the inner key name is unknown. Overrides are dropped with a warning until a real STIG Viewer 3 file is available.
