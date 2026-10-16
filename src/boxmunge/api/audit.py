# SPDX-License-Identifier: Apache-2.0
"""The action audit log: logs/audit.jsonl, one JSON object per line.

invoke() writes a "refused" record for every refusal, and for every call
that is not observe an "accepted" record before anything runs and a
"succeeded" or "failed" record when it ends. Auditing fails closed: if the
accepted record cannot be written, the call does not run.

Refusals record no parameters: they were never validated, so nothing in
them is known to be safe to log. Accepted and outcome records carry the
parameters with every schema property marked `secret` replaced by
"<redacted>".
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.api.principal import Principal
from boxmunge.api.schema import schema_types

AUDIT_MODE = 0o640
REDACTED = "<redacted>"
OUTCOMES = ("refused", "accepted", "succeeded", "failed")


class AuditError(Exception):
    """The audit log could not be appended to."""


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, record: dict[str, Any]) -> None:
        """Append one record and fsync it. Raises AuditError on any failure."""
        line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, AUDIT_MODE)
            try:
                written = os.write(fd, line)
                if written != len(line):
                    raise AuditError(f"short write to {self.path}: {written} of {len(line)} bytes")
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as e:
            raise AuditError(f"cannot append to {self.path}: {e}") from e


def audit_record(principal: Principal, action: str, outcome: str, *,
                 params: dict[str, Any] | None = None,
                 code: str | None = None, message: str | None = None) -> dict[str, Any]:
    """One audit line. *params* must already be redacted."""
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown audit outcome {outcome!r}")
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "principal": principal.id,
        "action": action,
        "outcome": outcome,
        "params": params,
    }
    if code is not None:
        record["code"] = code
    if message is not None:
        record["message"] = message
    return record


def redact(schema: dict[str, Any], value: Any) -> Any:
    """*value* with every property its schema marks secret replaced."""
    if isinstance(value, dict) and "object" in schema_types(schema):
        properties = schema.get("properties", {})
        return {
            key: REDACTED if properties.get(key, {}).get("secret") is True
            else redact(properties.get(key, {}), item)
            for key, item in value.items()
        }
    if isinstance(value, list) and "items" in schema:
        return [redact(schema["items"], item) for item in value]
    return value
