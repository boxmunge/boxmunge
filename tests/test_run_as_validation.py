"""security.user values and compose user: ranges (D11)."""
from __future__ import annotations

import pytest

from boxmunge.run_as import compose_user_problems, declared_user, validate_user_field
from boxmunge.security_overlay import SecurityValidationError, validate_security_block


@pytest.mark.parametrize("block", [
    {"user": "10001:10001"}, {"user": "1:1"}, {"user": "65535:65535"},
    {"user": "root", "reason": "entrypoint drops privileges"},
    {"user": "image", "reason": "postgres entrypoint drops to postgres"},
])
def test_valid_values(block) -> None:
    validate_user_field(block, "service:db")
    validate_security_block(block, "service:db")


@pytest.mark.parametrize("block, match", [
    ({"user": "root"}, "needs a non-empty reason"),
    ({"user": "image", "reason": "  "}, "needs a non-empty reason"),
    ({"user": "0:0"}, "between 1 and 65535"),
    ({"user": "10001:0"}, "between 1 and 65535"),
    ({"user": "65536:1"}, "between 1 and 65535"),
    ({"user": "10001"}, "between 1 and 65535"),
    ({"user": "postgres"}, "between 1 and 65535"),
    ({"user": 10001}, "must be a string"),
    ({"user": True}, "must be a string"),
])
def test_invalid_values(block, match) -> None:
    with pytest.raises(SecurityValidationError, match=match):
        validate_security_block(block, "service:db")


def test_service_declaration_overrides_the_project_default() -> None:
    assert declared_user({"user": "2000:2000"}, None) == ("2000:2000", None)
    assert declared_user({"user": "2000:2000"},
                         {"security": {"user": "image", "reason": "r"}}) == ("image", "r")


@pytest.mark.parametrize("user, ok", [
    ("1000", True), (1000, True), ("postgres", True), ("postgres:postgres", True),
    ("0:0", True), ("65535:65535", True), ("70000", False), ("1000:70000", False), ("", False),
])
def test_compose_user_ranges(user, ok) -> None:
    problems = compose_user_problems({"web": {"user": user}}, {"web": {}})
    assert (problems == []) is ok, problems


def test_compose_user_and_service_security_user_conflict() -> None:
    problems = compose_user_problems(
        {"web": {"user": "1000"}},
        {"web": {"security": {"user": "2000:2000"}}})
    assert problems and "keep one" in problems[0]


def test_project_default_does_not_conflict_with_compose_user() -> None:
    assert compose_user_problems({"web": {"user": "1000"}}, {"web": {}}) == []
