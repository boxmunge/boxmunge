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
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.api.schema import schema_types

AUDIT_MODE = 0o640
REDACTED = "<redacted>"
OUTCOMES = ("refused", "accepted", "succeeded", "failed")


class AuditError(Exception):
    """The audit log could not be appended to."""


class AuditLog:
    """*create* is True only for the dev apid and tests. In production the
    log is made, sealed append-only, by install; a missing one is an error."""

    def __init__(self, path: Path, *, create: bool) -> None:
        self.path = path
        self._create = create

    def append(self, record: dict[str, Any]) -> None:
        """Append one record and fsync it. Raises AuditError on any failure."""
        line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
        if self._create:
            flags |= os.O_CREAT
        try:
            try:
                fd = os.open(self.path, flags, AUDIT_MODE)
            except FileNotFoundError:
                if self._create:
                    raise
                raise AuditError(
                    f"{self.path}: logs/audit.jsonl is missing. "
                    "Recreate it as root with: boxmunge-server _audit-seal") from None
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise AuditError(f"cannot append to {self.path}: not a regular file")
                written = os.write(fd, line)
                if written != len(line):
                    raise AuditError(f"short write to {self.path}: {written} of {len(line)} bytes")
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as e:
            raise AuditError(f"cannot append to {self.path}: {e}") from e


def audit_record(principal_id: str, action: str, outcome: str, *,
                 params: dict[str, Any] | None = None,
                 code: str | None = None, message: str | None = None,
                 job: str | None = None) -> dict[str, Any]:
    """One audit line. *params* must already be redacted."""
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown audit outcome {outcome!r}")
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "principal": principal_id,
        "action": action,
        "outcome": outcome,
        "params": params,
    }
    if code is not None:
        record["code"] = code
    if message is not None:
        record["message"] = message
    if job is not None:
        record["job"] = job
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
