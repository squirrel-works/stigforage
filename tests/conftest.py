from __future__ import annotations

import itertools
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from stigforage.cci import CciList, load_cci_list, loads_cci_list

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


CCI_NS = "http://iase.disa.mil/cci"


def cci_xml(*items: str, root: str = "cci_list") -> bytes:
    """A CCI list document in DISA's layout, holding the given cci_item elements."""
    body = "".join(items)
    return (
        f'<{root} xmlns="{CCI_NS}"><metadata><version>test</version></metadata>'
        f"<cci_items>{body}</cci_items></{root}>"
    ).encode()


def cci_item(cci: str, *refs: tuple[str, str], status: str = "draft") -> str:
    """One cci_item with (version, index) references."""
    xml_refs = "".join(f'<reference version="{v}" index="{ix}"/>' for v, ix in refs)
    return (
        f'<cci_item id="{cci}"><status>{status}</status>'
        f"<references>{xml_refs}</references></cci_item>"
    )


# The shapes DISA's real list uses (ADR 0005), in a list small enough to read. CCI-000366 and
# CCI-000213 are real CCIs used by the fixture checklists, with their real Revision 5 mappings.
SYNTHETIC_CCI_XML = cci_xml(
    cci_item("CCI-000366", ("4", "CM-6 b"), ("5", "CM-6 b")),
    cci_item("CCI-000015", ("5", "AC-2 (1)")),
    cci_item("CCI-002132", ("4", "AC-2 (4)")),  # Revision 4 only: unmapped for Revision 5
    cci_item("CCI-003658", ("5", "SA-11 (6)"), status="deprecated"),
    cci_item("CCI-000213", ("5", "AC-3"), ("5", "AC-3 (2)")),  # two references
)


@pytest.fixture
def synthetic_cci_list() -> CciList:
    return loads_cci_list(SYNTHETIC_CCI_XML, source="synthetic")


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
