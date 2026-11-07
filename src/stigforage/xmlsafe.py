"""Hardened XML parsing on the standard library only.

Why not xml.etree.ElementTree.fromstring: it accepts DTDs and entity declarations, which is how
entity-expansion ("billion laughs") and external-entity attacks work. STIG, XCCDF and CKL files
never need a DTD, so this module refuses any document that contains one. The check is done by
expat itself via its doctype/entity callbacks rather than by scanning bytes, so it also holds for
UTF-16 and other encodings a byte scan would miss.

Namespaces are returned in ElementTree's `{uri}local` form, so results work with the normal
ElementTree API.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, NoReturn
from xml.parsers import expat

from stigforage.model import ChecklistError

__all__ = ["MAX_DEPTH", "UnsafeXmlError", "local_name", "parse_xml"]

# Real documents nest fewer than 20 levels; this stops pathological depth.
MAX_DEPTH = 256


class UnsafeXmlError(ChecklistError):
    """The document contains a DTD or entity declaration, which this tool never accepts."""


def local_name(tag: str) -> str:
    """Strip the `{namespace}` prefix from an ElementTree tag."""
    return tag.rsplit("}", 1)[-1]


def _qname(name: str) -> str:
    # expat with namespace_separator="}" reports "uri}local"; ElementTree wants "{uri}local".
    return "{" + name if "}" in name else name


def parse_xml(data: bytes, *, source: str = "XML") -> ET.Element:
    """Parse untrusted XML bytes into an Element tree. Raises ChecklistError on any problem."""
    parser = expat.ParserCreate(namespace_separator="}")
    parser.buffer_text = True
    stack: list[ET.Element] = []
    roots: list[ET.Element] = []

    def refuse(*_args: Any) -> NoReturn:
        raise UnsafeXmlError(f"{source}: DTD or entity declarations are not accepted")

    def start(name: str, attrs: dict[str, str]) -> None:
        if len(stack) >= MAX_DEPTH:
            raise ChecklistError(f"{source}: XML nesting deeper than {MAX_DEPTH} levels")
        element = ET.Element(_qname(name), {_qname(k): v for k, v in attrs.items()})
        if stack:
            stack[-1].append(element)
        else:
            roots.append(element)
        stack.append(element)

    def end(_name: str) -> None:
        stack.pop()

    def text(data: str) -> None:
        if not stack:
            return
        top = stack[-1]
        if len(top):
            top[-1].tail = (top[-1].tail or "") + data
        else:
            top.text = (top.text or "") + data

    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.NotationDeclHandler = refuse
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ChecklistError(
            f"{source}: invalid XML at line {exc.lineno} column {exc.offset}: "
            f"{expat.ErrorString(exc.code)}"
        ) from exc
    if not roots:
        raise ChecklistError(f"{source}: no root element")
    return roots[0]
