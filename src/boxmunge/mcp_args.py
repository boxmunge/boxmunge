# SPDX-License-Identifier: Apache-2.0
"""Check an MCP tool call's arguments against the tool's input schema.

The CLI parses argv and prints usage on a bad value; MCP hands the handler
whatever JSON the client sent. So before a handler runs: no unknown or
missing arguments, each value of its schema type, project names in the
project-name form, and no string that starts with '-', which a handler
passing it on as argv would read as an option.

The items of an array argument are exempt from the '-' rule by design:
the one such argument, `secrets`'s `args`, is an argv the secrets command
parses itself, where an option is meant to be one.
"""
from __future__ import annotations

from typing import Any

from boxmunge.paths import InvalidProjectName, validate_project_name

_TYPES: dict[str, type] = {"string": str, "integer": int, "boolean": bool, "array": list}
_PROJECT_KEYS = frozenset({"project", "name"})


def _value_problem(key: str, spec: dict[str, Any], value: Any) -> str | None:
    kind = spec["type"]
    if not isinstance(value, _TYPES[kind]) or (kind == "integer" and isinstance(value, bool)):
        return f"{key} must be {kind}, got {type(value).__name__} {value!r}"
    if kind == "array" and not all(isinstance(item, str) for item in value):
        return f"{key} must be an array of strings, got {value!r}"
    if not isinstance(value, str):
        return None
    if key in _PROJECT_KEYS:
        try:
            validate_project_name(value)
        except InvalidProjectName as e:
            return str(e)
    if value.startswith("-"):
        return f"{key} {value!r} may not start with '-': it would be read as an option"
    return None


def argument_problem(schema: dict[str, Any], arguments: Any) -> str | None:
    """Why `arguments` do not fit `schema`, or None if they do."""
    if not isinstance(arguments, dict):
        return f"arguments must be an object, got {type(arguments).__name__}"
    properties = schema.get("properties") or {}
    unknown = sorted(set(arguments) - set(properties))
    if unknown:
        return (f"unknown argument(s) {', '.join(unknown)}; this tool takes "
                f"{', '.join(sorted(properties)) or 'no arguments'}")
    missing = [key for key in schema.get("required", ()) if key not in arguments]
    if missing:
        return f"missing required argument(s): {', '.join(missing)}"
    for key, value in arguments.items():
        problem = _value_problem(key, properties[key], value)
        if problem:
            return problem
    return None
