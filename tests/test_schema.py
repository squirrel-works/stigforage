"""Subset JSON-Schema validator and `validate --schema` behaviour."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path
from typing import Any

import pytest

from conftest import FIXTURES
from stigforage import ckl, cklb, xccdf
from stigforage.cli import EXIT_INVALID, EXIT_OK, EXIT_UNREADABLE, run
from stigforage.schema import SchemaError, check_supported, validate_instance

SCHEMA_PATH = FIXTURES / "schema" / "SV3_CKLB_1_0_JSON_SCHEMA.json"
SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text("utf-8"))
VPN_CKL = FIXTURES / "ckl" / "Asset_a-VPN_TRUNCATED-V2R5.ckl"
RHEL9 = FIXTURES / "xccdf" / "U_RHEL_9_STIG_V1R1_Manual-xccdf-truncated.xml"


def _errors(instance: Any, schema: dict[str, Any]) -> list[str]:
    return [f"{i.path}: {i.message}" for i in validate_instance(instance, schema)]


def _cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return run(list(argv), out=out), out.getvalue()


@pytest.mark.parametrize(
    ("schema", "good", "bad"),
    [
        ({"type": "string"}, "a", 1),
        ({"type": "integer"}, 3, 3.5),
        ({"type": "integer"}, 3, True),  # bool is not an integer in JSON
        ({"type": ["string", "null"]}, None, 1),
        ({"enum": ["a", "b"]}, "a", "c"),
        ({"const": "1.0"}, "1.0", "2.0"),
        ({"type": "object", "required": ["x"]}, {"x": 1}, {}),
        ({"type": "object", "properties": {"x": {"type": "string"}}}, {"x": "a"}, {"x": 1}),
        ({"type": "object", "additionalProperties": False}, {}, {"y": 1}),
        ({"type": "object", "additionalProperties": {"type": "string"}}, {"y": "a"}, {"y": 1}),
        (
            {"type": "object", "patternProperties": {"^[a-z]+$": {"type": "string"}}},
            {"abc": "x"},
            {"abc": 1},
        ),
        ({"type": "array", "items": {"type": "string"}}, ["a"], ["a", 2]),
    ],
)
def test_keyword_accepts_good_and_rejects_bad(schema: dict[str, Any], good: Any, bad: Any) -> None:
    assert _errors(good, schema) == []
    assert _errors(bad, schema) != []


def test_ref_to_defs_is_resolved() -> None:
    schema = {"$defs": {"s": {"type": "string"}}, "properties": {"a": {"$ref": "#/$defs/s"}}}
    assert _errors({"a": "x"}, schema) == []
    assert _errors({"a": 1}, schema) == ["$.a: expected string, got integer"]


def test_dangling_ref_raises() -> None:
    with pytest.raises(SchemaError, match="nope"):
        validate_instance({"a": 1}, {"properties": {"a": {"$ref": "#/$defs/nope"}}})


def test_error_paths_index_into_arrays() -> None:
    schema = {"properties": {"l": {"items": {"properties": {"k": {"type": "string"}}}}}}
    assert _errors({"l": ["x", {"k": 1}]}, schema)[0].startswith("$.l[1].k:")


def test_uuid_format_is_a_warning_not_an_error() -> None:
    schema = {"type": "string", "format": "uuid"}
    issues = validate_instance("not-a-uuid", schema)
    assert [i.level for i in issues] == ["warning"]
    assert validate_instance("2f714970-8242-11ee-8b44-13c1c13d16bb", schema) == []


@pytest.mark.parametrize("keyword", ["oneOf", "anyOf", "allOf", "not", "pattern", "minLength"])
def test_unsupported_keywords_fail_loudly_instead_of_passing(keyword: str) -> None:
    with pytest.raises(SchemaError, match=keyword):
        check_supported({"type": "string", keyword: []})
    with pytest.raises(SchemaError, match=keyword):
        validate_instance("x", {"properties": {"a": {keyword: []}}})


def test_annotation_keywords_are_ignored() -> None:
    check_supported({"type": "string", "description": "d", "Description": "D", "title": "t"})


def test_disa_schema_is_fully_supported() -> None:
    check_supported(SCHEMA)


def test_disa_schema_rejects_known_bad_documents() -> None:
    uid = "2f714970-8242-11ee-8b44-13c1c13d16bb"
    assert _errors({"title": "t", "id": uid}, SCHEMA) == []
    assert any("required" in e for e in _errors({"title": "t"}, SCHEMA))
    assert any(
        "additional property" in e for e in _errors({"title": "t", "id": uid, "x": 1}, SCHEMA)
    )
    assert any(
        "2.0" in e or "1.0" in e
        for e in _errors({"title": "t", "id": uid, "cklb_version": "2.0"}, SCHEMA)
    )


def test_generated_ckl_import_is_schema_valid() -> None:
    doc = cklb.to_dict(ckl.load(VPN_CKL).checklist)
    assert _errors(doc, SCHEMA) == []


def test_generated_xccdf_import_is_schema_valid() -> None:
    doc = cklb.to_dict(xccdf.load(RHEL9).checklist)
    assert _errors(doc, SCHEMA) == []


def test_generated_output_survives_a_json_round_trip_schema_valid() -> None:
    text = cklb.dumps(ckl.load(VPN_CKL).checklist)
    assert _errors(json.loads(text), SCHEMA) == []


def test_public_stig_manager_cklb_is_reported_invalid() -> None:
    """The oracle files are real third-party output; the schema rejects them (nulls, version)."""
    doc = json.loads(
        (FIXTURES / "ckl" / "Asset_a-VPN_TRUNCATED-V2R5.oracle.cklb").read_text("utf-8-sig")
    )
    errors = _errors(doc, SCHEMA)
    assert any("additional property 'version'" in e for e in errors)
    assert any("got null" in e for e in errors)


def test_cli_validate_schema_ok_for_converted_inputs() -> None:
    code, out = _cli("validate", "--schema", str(SCHEMA_PATH), str(VPN_CKL), str(RHEL9))
    assert code == EXIT_OK, out
    assert "error" not in out


def test_cli_validate_schema_flags_raw_cklb_and_groups_repeats() -> None:
    raw = FIXTURES / "ckl" / "Asset_a-VPN_TRUNCATED-V2R5.oracle.cklb"
    code, out = _cli("validate", "--schema", str(SCHEMA_PATH), str(raw))
    assert code == EXIT_INVALID
    assert "(x" in out and "first at" in out  # repeated null-field errors collapsed


def test_cli_validate_schema_unreadable_or_unsupported_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = _cli("validate", "--schema", str(tmp_path / "missing.json"), str(VPN_CKL))
    assert code == EXIT_UNREADABLE
    bad = tmp_path / "bad.json"
    bad.write_text('{"oneOf": []}', "utf-8")
    code, _ = _cli("validate", "--schema", str(bad), str(VPN_CKL))
    assert code == EXIT_UNREADABLE
    assert "oneOf" in capsys.readouterr().err  # failure reason is logged, not printed to stdout
    notjson = tmp_path / "notjson.json"
    notjson.write_text("{nope", "utf-8")
    assert _cli("validate", "--schema", str(notjson), str(VPN_CKL))[0] == EXIT_UNREADABLE


def _ref_paths(jsonschema: Any, instance: Any) -> list[str]:
    """Error locations as the reference implementation sees them, in our path notation."""
    paths: list[str] = []
    for err in jsonschema.Draft201909Validator(SCHEMA).iter_errors(instance):
        base = "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in err.absolute_path)
        if err.validator == "additionalProperties":
            # jsonschema reports the parent; we report each offending property.
            paths += [f"{base}.{n}" for n in re.findall(r"'([^']+)'", err.message)]
        else:
            paths.append(base)
    return sorted(paths)


def test_jsonschema_oracle_agrees_on_error_paths() -> None:
    """Optional cross-check against the reference implementation (not a project dependency)."""
    jsonschema = pytest.importorskip("jsonschema")
    for name in ("Asset_a-VPN_TRUNCATED-V2R5.oracle.cklb",):
        raw = json.loads((FIXTURES / "ckl" / name).read_text("utf-8-sig"))
        mine = sorted(i.path for i in validate_instance(raw, SCHEMA) if i.level == "error")
        assert mine == _ref_paths(jsonschema, raw)
    for path in sorted((FIXTURES / "cklb").glob("*.cklb")):
        raw = json.loads(path.read_text("utf-8-sig"))
        mine = sorted(i.path for i in validate_instance(raw, SCHEMA) if i.level == "error")
        assert mine == _ref_paths(jsonschema, raw), path.name
