"""Validate documents against the JSON Schema subset used by the DISA CKLB schema.

Why not the `jsonschema` package: its dependency tree includes a compiled Rust extension
(`rpds-py`), which is a poor fit for offline, multi-platform bundles. The DISA schema only needs
the keywords listed in `_VALIDATING`, so this module implements exactly those and *refuses* any
schema that uses something else, rather than silently ignoring it and reporting a false pass.
`tests/test_schema.py` cross-checks verdicts against `jsonschema` when it is installed.

Format assertions: `format: uuid` is checked and reported as a warning, because JSON Schema
treats `format` as an annotation unless a consumer opts in.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, Literal

from stigforage.model import ChecklistError, Issue

__all__ = ["SchemaError", "check_supported", "validate_instance"]

# Keywords that do not affect validation. Includes the capitalised "Description" the DISA schema
# contains in one place.
_ANNOTATIONS = frozenset(
    {"$schema", "$id", "$comment", "title", "description", "Description", "default", "examples"}
)
_VALIDATING = frozenset(
    {
        "type",
        "const",
        "enum",
        "required",
        "properties",
        "additionalProperties",
        "patternProperties",
        "items",
        "$ref",
        "$defs",
        "format",
    }
)
_SCHEMA_MAPS = ("properties", "patternProperties", "$defs")  # name -> subschema
_SUPPORTED_FORMATS = frozenset({"uuid"})


class SchemaError(ChecklistError):
    """The schema is malformed or uses a keyword this validator does not implement."""


def check_supported(schema: Any, path: str = "#") -> None:
    """Raise SchemaError unless every keyword in `schema` is implemented here."""
    if not isinstance(schema, dict):
        raise SchemaError(f"{path}: schema must be an object")
    for key, value in schema.items():
        if key in _ANNOTATIONS:
            continue
        if key not in _VALIDATING:
            raise SchemaError(f"{path}: unsupported schema keyword {key!r}")
        _check_keyword(key, value, path)


def _check_keyword(key: str, value: Any, path: str) -> None:
    if key in _SCHEMA_MAPS:
        if not isinstance(value, dict):
            raise SchemaError(f"{path}/{key}: must be an object")
        for name, sub in value.items():
            check_supported(sub, f"{path}/{key}/{name}")
    elif key == "items":
        check_supported(value, f"{path}/items")
    elif key == "additionalProperties":
        if isinstance(value, dict):
            check_supported(value, f"{path}/additionalProperties")
        elif not isinstance(value, bool):
            raise SchemaError(f"{path}/additionalProperties: must be boolean or object")
    elif key == "format" and value not in _SUPPORTED_FORMATS:
        raise SchemaError(f"{path}/format: unsupported format {value!r}")
    elif key == "$ref" and not (isinstance(value, str) and value.startswith("#/")):
        raise SchemaError(f"{path}/$ref: only local '#/...' references are supported")


def _resolve(root: dict[str, Any], ref: str) -> dict[str, Any]:
    node: Any = root
    for part in ref.removeprefix("#/").split("/"):
        if not isinstance(node, dict) or part not in node:
            raise SchemaError(f"unresolvable $ref {ref!r}")
        node = node[part]
    if not isinstance(node, dict):
        raise SchemaError(f"$ref {ref!r} does not point at a schema object")
    return node


def _is_integer(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)) or (
        isinstance(value, float) and value.is_integer()
    )


# bool is an int subclass in Python but a separate JSON type, hence the explicit exclusions.
_TYPE_CHECKS: dict[str, Callable[[Any], bool]] = {
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "integer": _is_integer,
    "number": lambda v: isinstance(v, int | float) and not isinstance(v, bool),
}


def _is_type(value: Any, name: str) -> bool:
    check = _TYPE_CHECKS.get(name)
    if check is None:
        raise SchemaError(f"unsupported type name {name!r}")
    return check(value)


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    return {str: "string", int: "integer", float: "number", dict: "object", list: "array"}.get(
        type(value), type(value).__name__
    )


def _loc(parent: str, key: str | int) -> str:
    return f"{parent}[{key}]" if isinstance(key, int) else f"{parent}.{key}"


def validate_instance(instance: Any, schema: dict[str, Any]) -> list[Issue]:
    """Return every violation of `schema` found in `instance` (empty list means valid)."""
    check_supported(schema)
    issues: list[Issue] = []

    def err(path: str, message: str, level: Literal["error", "warning"] = "error") -> None:
        issues.append(Issue(level, path, message))

    def walk(value: Any, sub: dict[str, Any], path: str) -> None:
        if "$ref" in sub:
            walk(value, _resolve(schema, sub["$ref"]), path)
        if "type" in sub:
            names = [sub["type"]] if isinstance(sub["type"], str) else list(sub["type"])
            if not any(_is_type(value, n) for n in names):
                err(path, f"expected {' or '.join(names)}, got {_json_type(value)}")
                return
        if "const" in sub and value != sub["const"]:
            err(path, f"must equal {sub['const']!r}, got {value!r}")
        if "enum" in sub and value not in sub["enum"]:
            err(path, f"{value!r} is not one of {sub['enum']}")
        if sub.get("format") == "uuid" and isinstance(value, str) and not _is_uuid(value):
            err(path, f"{value!r} is not a UUID", "warning")
        if isinstance(value, dict):
            walk_object(value, sub, path)
        elif isinstance(value, list) and "items" in sub:
            for i, item in enumerate(value):
                walk(item, sub["items"], _loc(path, i))

    def walk_object(value: dict[str, Any], sub: dict[str, Any], path: str) -> None:
        props: dict[str, Any] = sub.get("properties", {})
        patterns: dict[str, Any] = sub.get("patternProperties", {})
        for name in sub.get("required", []):
            if name not in value:
                err(path, f"missing required property {name!r}")
        for name, item in value.items():
            child = _loc(path, name)
            matched = False
            if name in props:
                matched = True
                walk(item, props[name], child)
            for pattern, pattern_schema in patterns.items():
                if re.search(pattern, name):
                    matched = True
                    walk(item, pattern_schema, child)
            if not matched:
                extra = sub.get("additionalProperties", True)
                if extra is False:
                    err(child, f"additional property {name!r} is not allowed")
                elif isinstance(extra, dict):
                    walk(item, extra, child)

    walk(instance, schema, "$")
    return issues


_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _is_uuid(text: str) -> bool:
    # Canonical 8-4-4-4-12 form only; uuid.UUID() would also accept braces, URNs and bare hex.
    return _UUID_RE.match(text) is not None
