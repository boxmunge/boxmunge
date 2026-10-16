# SPDX-License-Identifier: Apache-2.0
"""What an action call returns: ActionResult on success, ActionError otherwise.

ErrorCode and HTTP_STATUS are the error-code table of the plugin contract
(docs/PLUGIN_API.md). Every error carries a code, a message that says what
to do next, and optional details.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ErrorCode(Enum):
    INVALID_PARAMS = "invalid_params"
    NOT_FOUND = "not_found"
    FORBIDDEN = "forbidden"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    BUSY = "busy"
    CONFLICT = "conflict"
    STALE_APPROVAL = "stale_approval"
    GOVERNED_CHANGE = "governed_change"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.INVALID_PARAMS: 422,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.APPROVAL_REQUIRED: 401,
    ErrorCode.APPROVAL_INVALID: 401,
    ErrorCode.BUSY: 409,
    ErrorCode.CONFLICT: 409,
    ErrorCode.STALE_APPROVAL: 409,
    ErrorCode.GOVERNED_CHANGE: 403,
    ErrorCode.FAILED: 500,
    ErrorCode.UNAVAILABLE: 503,
}


class ActionError(Exception):
    """An action call that was refused, or ran and failed."""

    def __init__(self, code: ErrorCode, message: str,
                 details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    @property
    def http_status(self) -> int:
        return HTTP_STATUS[self.code]

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"code": self.code.value, "message": self.message}
        if self.details is not None:
            body["details"] = self.details
        return body


@dataclass(frozen=True)
class ActionResult:
    """A successful inline call: the action's name and its typed result."""

    action: str
    data: dict[str, Any]
