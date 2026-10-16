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


@pytest.mark.parametrize("rule", [
    "MUST ignore result fields they do not know",
    "MUST treat an enum value they do not know as \"other\"",
    "MUST ignore `details` keys they do not know",
    "MUST treat an error code they do not know as `failed`",
    "`api_version` is `1.<minor>`",
])
def test_client_tolerance_and_versioning_are_pinned(rule) -> None:
    assert rule in DOC


def test_the_closed_schema_claim_is_internal_only() -> None:
    assert "a result never carries a field its schema does not declare" not in DOC


def test_job_invocation_contract_is_documented() -> None:
    assert "HTTP 202" in DOC and "`data` is the job record" in DOC
    assert "`result`" in DOC.split("### Jobs", 1)[1]


def test_value_conventions_are_documented() -> None:
    assert "ISO 8601 in UTC with a trailing `Z`" in DOC
    assert "Enum values are lowercase machine values" in DOC


def test_result_of_action_is_documented() -> None:
    assert "`x-result-of-action`" in DOC
    assert "treat `result` as any JSON value or null" in DOC


def test_transport_limits_are_documented() -> None:
    from boxmunge.api import server
    assert f"at most {server.MAX_CONNECTIONS} connections at once" in DOC
    assert f"within {server.REQUEST_TIMEOUT:g} seconds" in DOC
    assert "retry on `503`" in DOC
    assert "too many connections" in _error_row(ErrorCode.UNAVAILABLE)
