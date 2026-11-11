"""CCI to NIST SP 800-53 Revision 5 crosswalk, from DISA's CCI list (ADR 0005).

The list is not bundled: the user supplies DISA's `U_CCI_List.zip` or the `U_CCI_List.xml`
inside it (`--cci-list`), the same way STIGs are imported. Policy:

- Each CCI maps to the Revision 5 references DISA lists for it, kept as written (`CM-6 b`,
  `AC-2 (3) (d)`), and to the control each belongs to, in NIST's form: an enhancement is part of
  the control (`AC-2 (3) (d)` -> `AC-2(3)`), a part is not (`CP-9 (a)` -> `CP-9`). DISA writes
  some parts of a base control in parentheses, so a parenthesised number is an enhancement and
  a parenthesised letter a part.
- A CCI with no Revision 5 reference is unmapped; one missing from the list is unknown. Neither
  is ever filled in from Revision 4 or guessed. A deprecated CCI still maps when it has a
  Revision 5 reference, but is flagged.

Trust boundary: the list file is untrusted input. XML goes through `xmlsafe`; a ZIP is read in
memory with size caps and nothing is extracted to disk.
"""

from __future__ import annotations

import re
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from stigforage.fsio import MAX_BYTES, read_limited
from stigforage.model import ChecklistError
from stigforage.xmlsafe import local_name, parse_xml

__all__ = [
    "CciEntry",
    "CciList",
    "ControlRef",
    "RuleCrosswalk",
    "crosswalk",
    "load_cci_list",
    "loads_cci_list",
    "parse_reference",
]

_REV5 = "5"  # the `version` attribute DISA gives NIST SP 800-53 Revision 5 references
_ZIP_MAX_ENTRIES = 50  # DISA's zip holds 4 files
_XML_NAME = "U_CCI_List.xml"
_REFERENCE_RE = re.compile(r"^([A-Z]{2})-(\d+)(?:\s*\((\d+)\))?(?:\s|$)")


@dataclass(frozen=True)
class ControlRef:
    reference: str  # DISA's text, e.g. "AC-2 (3) (d)"
    control: str  # the control in NIST's form, e.g. "AC-2(3)"
    family: str  # e.g. "AC"


@dataclass(frozen=True)
class CciEntry:
    cci: str
    status: str  # "draft" for nearly all; "deprecated" for retired CCIs
    rev5: tuple[ControlRef, ...]

    @property
    def deprecated(self) -> bool:
        return self.status == "deprecated"


@dataclass(frozen=True)
class CciList:
    version: str  # DISA's list version, e.g. "2025-01-23"
    source: str
    entries: Mapping[str, CciEntry]


@dataclass
class RuleCrosswalk:
    """What a rule's CCIs map to, and every CCI that does not map cleanly."""

    references: list[ControlRef] = field(default_factory=list)  # distinct, first seen first
    unmapped: list[str] = field(default_factory=list)  # in the list, no Revision 5 reference
    unknown: list[str] = field(default_factory=list)  # not in the list at all
    deprecated: list[str] = field(default_factory=list)  # mapped, but retired by DISA

    @property
    def controls(self) -> list[str]:
        """Distinct controls in NIST's form, first seen first."""
        return list(dict.fromkeys(ref.control for ref in self.references))


def parse_reference(reference: str) -> ControlRef:
    """Split one of DISA's Revision 5 references into its control and family."""
    text = " ".join(reference.split())
    match = _REFERENCE_RE.match(text)
    if not match:
        raise ChecklistError(f"Revision 5 reference {reference!r} is not a NIST control")
    family, number, enhancement = match.groups()
    control = f"{family}-{number}" + (f"({enhancement})" if enhancement else "")
    return ControlRef(text, control, family)


def crosswalk(ccis: Iterable[str], cci_list: CciList) -> RuleCrosswalk:
    """Map a rule's CCIs to Revision 5, reporting every one that does not map."""
    result = RuleCrosswalk()
    seen: set[str] = set()
    for cci in dict.fromkeys(ccis):  # a rule can list a CCI twice; count it once
        entry = cci_list.entries.get(cci)
        if entry is None:
            result.unknown.append(cci)
            continue
        if not entry.rev5:
            result.unmapped.append(cci)
            continue
        if entry.deprecated:
            result.deprecated.append(cci)
        for ref in entry.rev5:
            if ref.reference not in seen:
                seen.add(ref.reference)
                result.references.append(ref)
    return result


def loads_cci_list(data: bytes, *, source: str = _XML_NAME) -> CciList:
    """Parse DISA's U_CCI_List.xml bytes."""
    root = parse_xml(data, source=source)
    if local_name(root.tag) != "cci_list":
        raise ChecklistError(
            f"{source}: root element {local_name(root.tag)!r} is not DISA's cci_list"
        )
    version = ""
    for meta in (c for c in root if local_name(c.tag) == "metadata"):
        version = next(((v.text or "").strip() for v in meta if local_name(v.tag) == "version"), "")
    entries: dict[str, CciEntry] = {}
    for i, item in enumerate(e for e in root.iter() if local_name(e.tag) == "cci_item"):
        cci = (item.get("id") or "").strip()
        if not cci:
            raise ChecklistError(f"{source}: cci_item[{i}] has no id")
        status = next(((c.text or "").strip() for c in item if local_name(c.tag) == "status"), "")
        refs: list[ControlRef] = []
        for ref in (r for r in item.iter() if local_name(r.tag) == "reference"):
            if ref.get("version") != _REV5:
                continue
            try:
                refs.append(parse_reference(ref.get("index", "")))
            except ChecklistError as exc:
                raise ChecklistError(f"{source}: {cci}: {exc}") from exc
        entries[cci] = CciEntry(cci, status, tuple(refs))
    if not entries:
        raise ChecklistError(f"{source}: no cci_item elements")
    return CciList(version, source, entries)


def _read_zip(path: Path) -> bytes:
    """The CCI list XML inside DISA's zip, read in memory with size caps."""
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > _ZIP_MAX_ENTRIES:
                raise ChecklistError(f"{path}: more than {_ZIP_MAX_ENTRIES} entries")
            named = [i for i in infos if i.filename.rsplit("/", 1)[-1] == _XML_NAME]
            xml = named or [i for i in infos if i.filename.lower().endswith(".xml")]
            if len(xml) != 1:
                raise ChecklistError(
                    f"{path}: expected one {_XML_NAME} (or exactly one .xml), found {len(xml)}"
                )
            entry = xml[0]
            if entry.file_size > MAX_BYTES:
                raise ChecklistError(f"{path}: {entry.filename!r} is over the size limit")
            with zf.open(entry) as fh:
                data = fh.read(MAX_BYTES + 1)  # the size in a ZIP header can lie
            if len(data) > MAX_BYTES:
                raise ChecklistError(f"{path}: {entry.filename!r} is over the size limit")
            return data
    except zipfile.BadZipFile as exc:
        raise ChecklistError(f"{path}: not a valid ZIP file: {exc}") from exc


def load_cci_list(path: Path) -> CciList:
    """Read DISA's U_CCI_List.zip or U_CCI_List.xml. Raises ChecklistError, OSError."""
    data = _read_zip(path) if path.suffix.lower() == ".zip" else read_limited(path)
    return loads_cci_list(data, source=str(path))
