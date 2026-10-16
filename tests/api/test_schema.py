# SPDX-License-Identifier: Apache-2.0
"""The registry's JSON Schema subset: definition checks, validation, builders."""
from __future__ import annotations

import pytest

from boxmunge.api.schema import (
    BOOLEAN, INTEGER, RESULT_OF_ACTION, STRING, SchemaDefinitionError, arr, check_schema,
    enum, nullable, obj, validate,
)

PROJECT = {"type": "string", "pattern": "[a-z0-9][a-z0-9-]{0,62}"}

VALID = [
    ({"type": "string"}, "x"),
    ({"type": ["string", "null"]}, None),
    ({"type": "integer", "minimum": 1, "maximum": 3}, 3),
    ({"type": "number"}, 1.5),
    ({"type": "number"}, 2),
    ({"type": "boolean"}, False),
    ({"type": "string", "minLength": 2, "maxLength": 3}, "abc"),
    (PROJECT, "shop"),
    ({"type": "string", "enum": ["a", "b"]}, "b"),
    ({"type": "integer", "const": 3}, 3),
    (arr(INTEGER), [1, 2]),
    (obj({"a": STRING, "b": INTEGER}, optional=("b",)), {"a": "x"}),
    (nullable(enum("a")), None),
    (nullable(obj({"a": STRING})), {"a": "x"}),
]


@pytest.mark.parametrize("schema,value", VALID)
def test_valid_values_pass(schema, value) -> None:
    check_schema(schema)
    assert validate(schema, value) == []


INVALID = [
    ({"type": "integer"}, True, "$: expected integer, got boolean"),
    ({"type": "integer"}, 1.0, "$: expected integer, got number"),
    ({"type": "number"}, False, "$: expected number, got boolean"),
    ({"type": "number"}, float("nan"), "$: expected number, got a non-finite number"),
    ({"type": "string"}, None, "$: expected string, got null"),
    (PROJECT, "shop\n", "$: does not match pattern"),
    (PROJECT, "../etc", "$: does not match pattern"),
    (PROJECT, "", "$: does not match pattern"),
    ({"type": "string", "minLength": 2}, "a", "$: shorter than 2 characters"),
    ({"type": "string", "maxLength": 2}, "abc", "$: longer than 2 characters"),
    ({"type": "integer", "minimum": 1}, 0, "$: below minimum 1"),
    ({"type": "integer", "maximum": 3}, 4, "$: above maximum 3"),
    ({"type": "string", "enum": ["a"]}, "b", "$: must be one of 'a'"),
    ({"type": "integer", "const": 1}, 2, "$: must be 1"),
    ({"type": "integer", "enum": [1]}, True, "$: expected integer, got boolean"),
    (arr(INTEGER), [1, "x"], "$[1]: expected integer, got string"),
    (obj({"a": STRING}), {}, "$: missing required property 'a'"),
    (obj({"a": STRING}), {"a": "x", "b": 1}, "$: unexpected property 'b'"),
    (obj({"a": obj({"b": INTEGER})}), {"a": {"b": "x"}}, "$.a.b: expected integer, got string"),
    (obj({"a": STRING}), ["a"], "$: expected object, got array"),
    (nullable(enum("a")), "b", "$: must be one of 'a', None"),
]


@pytest.mark.parametrize("schema,value,problem", INVALID)
def test_invalid_values_report_where_and_why(schema, value, problem) -> None:
    check_schema(schema)
    problems = validate(schema, value)
    assert any(p.startswith(problem) for p in problems), problems


def test_every_violation_is_reported() -> None:
    schema = obj({"a": STRING, "b": INTEGER})
    assert validate(schema, {"a": 1, "c": True}) == [
        "$: missing required property 'b'",
        "$: unexpected property 'c'",
        "$.a: expected string, got integer",
    ]


BAD_SCHEMAS = [
    ({"type": "object", "properties": {}}, "additionalProperties: false"),
    ({"type": "object", "additionalProperties": True, "properties": {}},
     "additionalProperties: false"),
    ({"type": "object", "additionalProperties": False}, "must declare properties"),
    ({"type": "string", "format": "date"}, "unsupported keyword(s): format"),
    ({"type": "array"}, "array schema must declare items"),
    ({"type": "strnig"}, "invalid type list"),
    ({"type": ["string", "string"]}, "invalid type list"),
    ({}, "type must be a type name"),
    ({"type": "string", "pattern": "("}, "pattern does not compile"),
    ({"type": "string", "properties": {}}, "object keywords on a non-object schema"),
    ({"type": "string", "items": STRING}, "items on a non-array schema"),
    ({"type": "object", "additionalProperties": False, "properties": {},
      "required": ["x"]}, "required names undeclared properties: x"),
    (obj({"a": {"type": "object", "properties": {}}}),
     "$.a: object schema must set additionalProperties: false"),
    (arr({"type": "object", "properties": {}}),
     "$[]: object schema must set additionalProperties: false"),
    ({"type": "integer", "minimum": True}, "minimum must be a number"),
    ({"type": "string", "enum": []}, "enum must be a non-empty list"),
    ({"type": "string", "secret": "yes"}, "secret must be true or false"),
]


@pytest.mark.parametrize("schema,message", BAD_SCHEMAS)
def test_schemas_outside_the_subset_are_rejected(schema, message) -> None:
    with pytest.raises(SchemaDefinitionError) as excinfo:
        check_schema(schema)
    assert message in str(excinfo.value)


def test_annotations_are_accepted_and_ignored() -> None:
    schema = {"type": "string", "description": "A token.", "secret": True}
    check_schema(schema)
    assert validate(schema, "s3cret") == []


def test_obj_requires_everything_not_optional() -> None:
    schema = obj({"a": STRING, "b": BOOLEAN, "c": INTEGER}, optional=("c",))
    assert schema == {
        "type": "object", "additionalProperties": False,
        "properties": {"a": STRING, "b": BOOLEAN, "c": INTEGER},
        "required": ["a", "b"],
    }


def test_obj_refuses_unknown_optional_names() -> None:
    with pytest.raises(SchemaDefinitionError, match="optional names undeclared"):
        obj({"a": STRING}, optional=("b",))


def test_nullable_adds_null_to_type_and_enum() -> None:
    assert nullable(enum("x", "y")) == {"type": ["string", "null"], "enum": ["x", "y", None]}
    assert nullable(STRING) == {"type": ["string", "null"]}


# ---------- x-result-of-action: a job record's result ----------


JOB_LIKE = obj({"action": STRING, "result": RESULT_OF_ACTION})
THING_RESULT = obj({"count": INTEGER})


def _results(name: str):
    return {"thing.get": THING_RESULT}.get(name)


def test_result_of_action_is_accepted_beside_an_action_property() -> None:
    check_schema(JOB_LIKE)
    check_schema(arr(JOB_LIKE))


@pytest.mark.parametrize("schema,message", [
    (RESULT_OF_ACTION, "only on a result property beside an action property"),
    (obj({"result": RESULT_OF_ACTION}), "only on a result property beside an action property"),
    (obj({"action": STRING, "other": RESULT_OF_ACTION}),
     "only on a result property beside an action property"),
    (obj({"action": STRING, "result": {**RESULT_OF_ACTION, "x-result-of-action": "yes"}}),
     "x-result-of-action must be true"),
    (obj({"action": STRING, "result": {**RESULT_OF_ACTION, "type": "object"}}),
     "x-result-of-action needs type [\"object\", \"null\"]"),
    (obj({"action": STRING, "result": {**RESULT_OF_ACTION, "properties": {}}}),
     "x-result-of-action takes no other validation keywords"),
])
def test_result_of_action_is_refused_anywhere_else(schema, message) -> None:
    with pytest.raises(SchemaDefinitionError) as excinfo:
        check_schema(schema)
    assert message in str(excinfo.value)


@pytest.mark.parametrize("value,problems", [
    ({"action": "thing.get", "result": None}, []),
    ({"action": "thing.get", "result": {"count": 3}}, []),
    ({"action": "thing.get", "result": {"count": "3"}},
     ["$.result.count: expected integer, got string"]),
    ({"action": "thing.get", "result": {"count": 3, "extra": 1}},
     ["$.result: unexpected property 'extra'"]),
    ({"action": "nope.nope", "result": {}}, ["$.result: unknown action 'nope.nope'"]),
    ({"action": "thing.get", "result": [1]}, ["$.result: expected object or null, got array"]),
])
def test_result_of_action_validates_against_the_named_action(value, problems) -> None:
    assert validate(JOB_LIKE, value, result_schemas=_results) == problems


def test_a_result_cannot_pass_unchecked_without_the_registry() -> None:
    assert validate(JOB_LIKE, {"action": "thing.get", "result": None}) == []
    assert validate(JOB_LIKE, {"action": "thing.get", "result": {"count": 3}}) == [
        "$.result: no action registry to check it against"]
