# SPDX-License-Identifier: Apache-2.0
"""The error-code table and the error body shape."""
from __future__ import annotations

from boxmunge.api.result import HTTP_STATUS, ActionError, ErrorCode

SPEC_TABLE = {
    "invalid_params": 422, "not_found": 404, "forbidden": 403,
    "approval_required": 401, "approval_invalid": 401, "busy": 409,
    "conflict": 409, "stale_approval": 409, "governed_change": 403,
    "failed": 500, "unavailable": 503,
}


def test_error_codes_match_the_contract() -> None:
    assert {code.value: status for code, status in HTTP_STATUS.items()} == SPEC_TABLE
    assert set(HTTP_STATUS) == set(ErrorCode)


def test_error_body_has_code_message_and_optional_details() -> None:
    plain = ActionError(ErrorCode.BUSY, "Try again shortly.")
    assert plain.to_dict() == {"code": "busy", "message": "Try again shortly."}
    assert plain.http_status == 409
    detailed = ActionError(ErrorCode.INVALID_PARAMS, "Bad.", {"violations": ["$: x"]})
    assert detailed.to_dict()["details"] == {"violations": ["$: x"]}
    assert str(detailed) == "Bad."
