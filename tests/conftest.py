from __future__ import annotations

import itertools
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

# Fields that legitimately differ between independently generated checklists.
VOLATILE = frozenset({"uuid", "stig_uuid", "STIGUuid", "createdAt", "updatedAt"})

# STIG Manager's CKLB output is not valid against the DISA schema (it nulls text fields, writes
# STIGUuid/createdAt/updatedAt as null/extra, and a stig-level `version`). We emit schema-valid
# output instead, so these keys are excluded when comparing against those oracles. Anything else
# must match exactly.
ORACLE_SCHEMA_DEVIATIONS = frozenset(
    {"mitigation_control", "responsibility", "ia_controls", "false_negatives", "false_positives",
     "security_override_guidance", "potential_impacts", "third_party_tools", "mitigations",
     "reference_identifier", "target_key"}
)  # fmt: skip


@pytest.fixture
def id_factory() -> Callable[[], str]:
    """Deterministic ids: two loads of the same file produce identical checklists."""
    counter = itertools.count(1)
    return lambda: f"id-{next(counter):04d}"


def rules_without(d: dict[str, Any], drop: frozenset[str] | set[str]) -> list[dict[str, Any]]:
    """All rules of all STIGs in a CKLB dict, minus the given keys."""
    return [{k: v for k, v in r.items() if k not in drop} for s in d["stigs"] for r in s["rules"]]


def stig_header(d: dict[str, Any]) -> dict[str, Any]:
    """First STIG's non-rule fields, minus its (random) uuid."""
    return {
        k: v
        for k, v in d["stigs"][0].items()
        if k not in {"rules", "uuid", "version", "reference_identifier"}
    }
