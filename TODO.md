# TODO

## Test tooling

Requested by the maintainer on 2026-11-10; not scheduled into a roadmap stage yet.

- Add `mutmut` (mutation testing). It would replace the hand-made mutation checks done for the
  V0.2.2 `merge` and `upgrade` units (see those commit messages).
- Add `pytest-benchmark` for performance checks, for example `upgrade` on a full-size STIG
  (RHEL 9 is 445 rules and took about 0.15 s by hand).
- `pytest` is already a dev dependency (pinned in `pyproject.toml`); nothing to add.

Before adding either, check it against the dependency criteria: maintained and popular,
permissive license, light transitive tree, and works offline. Both would be dev-only
dependencies, never runtime ones, pinned exactly like the other dev tools (ADR 0004).
