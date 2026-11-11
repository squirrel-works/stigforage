from __future__ import annotations

import itertools
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from stigforage.cci import CciList, load_cci_list

FIXTURES = Path(__file__).parent / "fixtures"

# DISA reference data is used for local tests only and never committed (maintainer's decision,
# ADR 0005): tests that need it skip when it is absent, as in CI. tests/fixtures/local/ is
# gitignored.
LOCAL = FIXTURES / "local"
DISA_CCI_ZIP = LOCAL / "U_CCI_List.zip"
DISA_CCI_URL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip"


@pytest.fixture(scope="session")
def disa_cci_list() -> CciList:
    """DISA's real CCI list, or a skip saying how to fetch it for local runs."""
    if not DISA_CCI_ZIP.is_file():
        pytest.skip(
            f"DISA CCI list not present (local-only test data). To run these tests: "
            f"mkdir -p {LOCAL} && curl -fsSo {DISA_CCI_ZIP} {DISA_CCI_URL}"
        )
    return load_cci_list(DISA_CCI_ZIP)


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
