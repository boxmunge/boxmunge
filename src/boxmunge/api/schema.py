# SPDX-License-Identifier: Apache-2.0
"""The JSON Schema subset the action registry uses, and builders for it.

Keywords: type, properties, required, additionalProperties (false only),
enum, pattern, minimum, maximum, minLength, maxLength, items, const.
Annotations that never affect validation: description, secret.

- check_schema(schema) raises SchemaDefinitionError unless the schema stays
  inside the subset: every schema names its type, every object schema
  declares its properties and sets additionalProperties: false, and every
  array schema declares items.
- validate(schema, value) returns each violation as "<path>: <problem>";
  an empty list means the value is valid.

Two rules are stricter than a general-purpose validator, on purpose:
- pattern must match the whole string (re.fullmatch), as if anchored at
  both ends, so "shop\\n" never passes a pattern written for "shop".
- JSON true and false are booleans only, never integers or numbers.
"""
from __future__ import annotations

import math
import re
from typing import Any

TYPES = ("object", "array", "string", "integer", "number", "boolean", "null")
_KEYWORDS = frozenset({
    "type", "properties", "required", "additionalProperties", "enum",
    "pattern", "minimum", "maximum", "minLength", "maxLength", "items",
    "const", "description", "secret",
})
_OBJECT_ONLY = ("properties", "required", "additionalProperties")
_BOUNDS = ("minimum", "maximum", "minLength", "maxLength")


class SchemaDefinitionError(ValueError):
    """A schema uses something outside the supported subset."""


def schema_types(schema: dict[str, Any]) -> tuple[str, ...]:
    """The type names a schema allows."""
    declared = schema.get("type")
    return (declared,) if isinstance(declared, str) else tuple(declared or ())


# ---------- schema definition checks ----------


def check_schema(schema: Any, path: str = "$") -> None:
    """Raise SchemaDefinitionError unless *schema* stays inside the subset."""
    if not isinstance(schema, dict):
        raise SchemaDefinitionError(f"{path}: a schema must be a mapping")
    unknown = sorted(set(schema) - _KEYWORDS)
    if unknown:
        raise SchemaDefinitionError(
            f"{path}: unsupported keyword(s): {', '.join(unknown)}")
    types = _checked_types(schema, path)
    if "object" in types:
        _check_object(schema, path)
    elif any(key in schema for key in _OBJECT_ONLY):
        raise SchemaDefinitionError(f"{path}: object keywords on a non-object schema")
    if "array" in types:
        if "items" not in schema:
            raise SchemaDefinitionError(f"{path}: array schema must declare items")
        check_schema(schema["items"], f"{path}[]")
    elif "items" in schema:
        raise SchemaDefinitionError(f"{path}: items on a non-array schema")
    _check_scalar_keywords(schema, path)


def _checked_types(schema: dict[str, Any], path: str) -> tuple[str, ...]:
    declared = schema.get("type")
    if isinstance(declared, str):
        types: tuple[str, ...] = (declared,)
    elif (isinstance(declared, list) and declared
          and all(isinstance(t, str) for t in declared)):
        types = tuple(declared)
    else:
        raise SchemaDefinitionError(
            f"{path}: type must be a type name or a non-empty list of them")
    if any(t not in TYPES for t in types) or len(set(types)) != len(types):
        raise SchemaDefinitionError(f"{path}: invalid type list {list(types)}")
    return types


def _check_object(schema: dict[str, Any], path: str) -> None:
    if schema.get("additionalProperties") is not False:
        raise SchemaDefinitionError(
            f"{path}: object schema must set additionalProperties: false")
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise SchemaDefinitionError(f"{path}: object schema must declare properties")
    for name, sub in properties.items():
        check_schema(sub, f"{path}.{name}")
    required = schema.get("required", [])
    if not isinstance(required, list) or len(set(required)) != len(required):
        raise SchemaDefinitionError(f"{path}: required must be a list of distinct names")
    missing = [name for name in required if name not in properties]
    if missing:
        raise SchemaDefinitionError(
            f"{path}: required names undeclared properties: {', '.join(missing)}")


def _check_scalar_keywords(schema: dict[str, Any], path: str) -> None:
    for key in _BOUNDS:
        if key in schema and not _is_number(schema[key]):
            raise SchemaDefinitionError(f"{path}: {key} must be a number")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            raise SchemaDefinitionError(f"{path}: pattern must be a string")
        try:
            re.compile(schema["pattern"])
        except re.error as e:
            raise SchemaDefinitionError(f"{path}: pattern does not compile: {e}") from e
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        raise SchemaDefinitionError(f"{path}: enum must be a non-empty list")
    if "secret" in schema and not isinstance(schema["secret"], bool):
        raise SchemaDefinitionError(f"{path}: secret must be true or false")
    if "description" in schema and not isinstance(schema["description"], str):
        raise SchemaDefinitionError(f"{path}: description must be a string")


# ---------- value validation ----------


def validate(schema: dict[str, Any], value: Any, path: str = "$") -> list[str]:
    """Every way *value* breaks *schema*, as "<path>: <problem>" strings."""
    types = schema_types(schema)
    if not any(_matches_type(value, name) for name in types):
        return [f"{path}: expected {' or '.join(types)}, got {_json_type(value)}"]
    problems: list[str] = []
    if "const" in schema and not _same(value, schema["const"]):
        problems.append(f"{path}: must be {schema['const']!r}")
    if "enum" in schema and not any(_same(value, option) for option in schema["enum"]):
        options = ", ".join(repr(option) for option in schema["enum"])
        problems.append(f"{path}: must be one of {options}")
    if isinstance(value, str):
        problems.extend(_string_problems(schema, value, path))
    elif _is_number(value):
        problems.extend(_number_problems(schema, value, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            problems.extend(validate(schema["items"], item, f"{path}[{index}]"))
    elif isinstance(value, dict):
        problems.extend(_object_problems(schema, value, path))
    return problems


def _string_problems(schema: dict[str, Any], value: str, path: str) -> list[str]:
    problems = []
    if "minLength" in schema and len(value) < schema["minLength"]:
        problems.append(f"{path}: shorter than {schema['minLength']} characters")
    if "maxLength" in schema and len(value) > schema["maxLength"]:
        problems.append(f"{path}: longer than {schema['maxLength']} characters")
    if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
        problems.append(f"{path}: does not match pattern {schema['pattern']!r}")
    return problems


def _number_problems(schema: dict[str, Any], value: float, path: str) -> list[str]:
    problems = []
    if "minimum" in schema and value < schema["minimum"]:
        problems.append(f"{path}: below minimum {schema['minimum']}")
    if "maximum" in schema and value > schema["maximum"]:
        problems.append(f"{path}: above maximum {schema['maximum']}")
    return problems


def _object_problems(schema: dict[str, Any], value: dict[str, Any], path: str) -> list[str]:
    properties = schema.get("properties", {})
    problems = [
        f"{path}: missing required property {name!r}"
        for name in schema.get("required", []) if name not in value
    ]
    if schema.get("additionalProperties") is False:
        problems.extend(
            f"{path}: unexpected property {name!r}"
            for name in value if name not in properties
        )
    for name, sub in properties.items():
        if name in value:
            problems.extend(validate(sub, value[name], f"{path}.{name}"))
    return problems


def _is_number(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _matches_type(value: Any, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return _is_number(value)
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, list)
    return isinstance(value, dict)


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number" if math.isfinite(value) else "a non-finite number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _same(a: Any, b: Any) -> bool:
    return isinstance(a, bool) == isinstance(b, bool) and a == b


# ---------- builders ----------
# Shared constants are plain dicts: never mutate one.

STRING: dict[str, Any] = {"type": "string"}
NULLABLE_STRING: dict[str, Any] = {"type": ["string", "null"]}
INTEGER: dict[str, Any] = {"type": "integer"}
NULLABLE_INTEGER: dict[str, Any] = {"type": ["integer", "null"]}
BOOLEAN: dict[str, Any] = {"type": "boolean"}
NULLABLE_BOOLEAN: dict[str, Any] = {"type": ["boolean", "null"]}


def obj(properties: dict[str, dict[str, Any]], *,
        optional: tuple[str, ...] = ()) -> dict[str, Any]:
    """A closed object schema. Every property is required unless optional."""
    unknown = [name for name in optional if name not in properties]
    if unknown:
        raise SchemaDefinitionError(
            f"optional names undeclared properties: {', '.join(unknown)}")
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": dict(properties),
        "required": [name for name in properties if name not in optional],
    }


def arr(items: dict[str, Any]) -> dict[str, Any]:
    """An array schema whose every item matches *items*."""
    return {"type": "array", "items": items}


def enum(*values: str) -> dict[str, Any]:
    """A string that must be one of *values*."""
    return {"type": "string", "enum": list(values)}


def nullable(schema: dict[str, Any]) -> dict[str, Any]:
    """*schema*, or null. An enum gains null as an allowed value too."""
    result = {**schema, "type": [*schema_types(schema), "null"]}
    if "enum" in schema:
        result["enum"] = [*schema["enum"], None]
    return result
