from __future__ import annotations

import pytest

from stigforage.model import ChecklistError
from stigforage.xmlsafe import MAX_DEPTH, UnsafeXmlError, local_name, parse_xml

BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>"""


def test_parses_text_tail_attributes_and_nesting() -> None:
    root = parse_xml(b'<a x="1">hi<b>one</b>mid<c/>end</a>')
    assert root.tag == "a"
    assert root.get("x") == "1"
    assert root.text == "hi"
    assert [c.tag for c in root] == ["b", "c"]
    assert root[0].text == "one"
    assert root[0].tail == "mid"
    assert root[1].tail == "end"


def test_namespaces_use_elementtree_form() -> None:
    root = parse_xml(b'<r xmlns="urn:a" xmlns:d="urn:d"><d:x d:k="v"/></r>')
    assert root.tag == "{urn:a}r"
    assert root[0].tag == "{urn:d}x"
    assert root[0].get("{urn:d}k") == "v"
    assert local_name(root[0].tag) == "x"
    assert local_name("plain") == "plain"


def test_standard_entities_and_char_refs_are_decoded() -> None:
    assert parse_xml(b"<a>&lt;&amp;&#65;&#x42;</a>").text == "<&AB"


@pytest.mark.parametrize(
    "payload",
    [
        BILLION_LAUGHS,
        b'<?xml version="1.0"?><!DOCTYPE a SYSTEM "http://evil.example/x.dtd"><a/>',
        b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>',
        b"<!DOCTYPE a><a/>",
    ],
    ids=["billion-laughs", "external-dtd", "external-entity", "bare-doctype"],
)
def test_dtd_and_entities_are_refused(payload: bytes) -> None:
    with pytest.raises(UnsafeXmlError, match="DTD or entity"):
        parse_xml(payload, source="t.xml")


def test_dtd_is_refused_in_utf16_too() -> None:
    # A byte-level scan for b"<!DOCTYPE" would miss this; expat's own callback does not.
    doc = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>'
    with pytest.raises(UnsafeXmlError):
        parse_xml(doc.encode("utf-16"))


def test_utf16_without_dtd_parses() -> None:
    doc = '<?xml version="1.0" encoding="UTF-16"?><a>ok</a>'
    assert parse_xml(doc.encode("utf-16")).text == "ok"


def test_utf8_bom_is_tolerated() -> None:
    assert parse_xml(b"\xef\xbb\xbf<a>ok</a>").text == "ok"


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        (b"<a><b></a>", r"t\.xml: invalid XML at line 1"),
        (b"", r"invalid XML"),
        (b"<a>&undefined;</a>", r"invalid XML"),
        (b"<a/><b/>", r"invalid XML"),
        (b"just text", r"invalid XML"),
    ],
)
def test_malformed_documents(payload: bytes, match: str) -> None:
    with pytest.raises(ChecklistError, match=match):
        parse_xml(payload, source="t.xml")


def test_excessive_nesting_is_refused() -> None:
    deep = b"<a>" * (MAX_DEPTH + 1) + b"</a>" * (MAX_DEPTH + 1)
    with pytest.raises(ChecklistError, match="nesting deeper"):
        parse_xml(deep)


def test_nesting_at_the_limit_is_accepted() -> None:
    ok = b"<a>" * MAX_DEPTH + b"</a>" * MAX_DEPTH
    assert parse_xml(ok).tag == "a"
