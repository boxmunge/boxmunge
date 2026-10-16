# SPDX-License-Identifier: Apache-2.0
"""docs/PLUGIN_API.md names every action and every error code the server has."""
from __future__ import annotations

from pathlib import Path

import pytest

from boxmunge.api import API_VERSION
from boxmunge.api.actions import build_registry
from boxmunge.api.result import HTTP_STATUS, ErrorCode

DOC = (Path(__file__).resolve().parents[2] / "docs" / "PLUGIN_API.md").read_text()


@pytest.mark.parametrize("action", build_registry().actions(), ids=lambda a: a.name)
def test_every_action_is_documented(action) -> None:
    assert f"`{action.name}`" in DOC


@pytest.mark.parametrize("code", list(ErrorCode), ids=lambda c: c.value)
def test_every_error_code_is_documented_with_its_status(code) -> None:
    assert f"| `{code.value}` | {HTTP_STATUS[code]} |" in DOC


def test_the_documented_version_is_the_served_one() -> None:
    assert f"API version: **{API_VERSION}**" in DOC


def _error_row(code: ErrorCode) -> str:
    return next(line for line in DOC.splitlines() if line.startswith(f"| `{code.value}` |"))


def test_a_missing_approval_is_documented_as_approval_required() -> None:
    """invoke() answers a plugin operate call that carries no approval with
    approval_required; approval_invalid is for an approval that was sent."""
    assert "without an approval" in _error_row(ErrorCode.APPROVAL_REQUIRED)
    assert "missing" not in _error_row(ErrorCode.APPROVAL_INVALID)


def test_project_health_is_documented_as_running_smoke_checks() -> None:
    assert "not free of side effects" in DOC.split("`project.health`", 2)[2]
