# SPDX-License-Identifier: Apache-2.0
"""Job records on disk, and the read side the jobs.* actions use.

Layout (the job runner writes it):
  state/jobs/queue/<id>.json     every unfinished job (queued or running)
  state/jobs/<id>.json           finished jobs (succeeded or failed)
  state/jobs/<id>.events.jsonl   the job's events, one JSON object per line

JOB_SCHEMA and EVENT_SCHEMA are the formats every writer must produce. A
record or event line that breaks them is reported as corrupt (StateError),
never skipped.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from boxmunge.api.schema import NULLABLE_STRING, STRING, enum, nullable, obj, validate
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError, read_state

JOB_ID_PATTERN = "[0-9A-HJKMNP-TV-Z]{26}"
_JOB_ID_RE = re.compile(JOB_ID_PATTERN)
JOB_STATES = ("queued", "running", "succeeded", "failed")
EVENT_TYPES = ("log", "step", "state")
STEP_STATUSES = ("started", "succeeded", "failed")

JOB_SCHEMA = obj({
    "id": {"type": "string", "pattern": JOB_ID_PATTERN},
    "action": STRING,
    "principal": STRING,
    "project": NULLABLE_STRING,
    "state": enum(*JOB_STATES),
    "created_at": STRING,
    "started_at": NULLABLE_STRING,
    "finished_at": NULLABLE_STRING,
    "error": nullable(obj({"code": STRING, "message": STRING})),
})

EVENT_SCHEMA = obj({
    "seq": {"type": "integer", "minimum": 1},
    "ts": STRING,
    "type": enum(*EVENT_TYPES),
    "message": STRING,
    "step": STRING,
    "status": enum(*STEP_STATUSES),
    "state": enum(*JOB_STATES),
}, optional=("message", "step", "status", "state"))


class JobStore:
    def __init__(self, paths: BoxPaths) -> None:
        self._done = paths.jobs_dir
        self._queue = paths.jobs_queue

    def get(self, job_id: str) -> dict[str, Any] | None:
        """The job's record, or None if there is no such job."""
        for directory in (self._queue, self._done):
            path = directory / f"{job_id}.json"
            if path.exists():
                return _load_record(path, job_id)
        return None

    def recent(self, *, project: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Jobs newest first, optionally for one project."""
        records: dict[str, dict[str, Any]] = {}
        # A job being finished can briefly sit in both directories; the
        # queue copy is written first, so it wins.
        for directory in (self._done, self._queue):
            if not directory.is_dir():
                continue
            for path in directory.glob("*.json"):
                if _JOB_ID_RE.fullmatch(path.stem):
                    records[path.stem] = _load_record(path, path.stem)
        jobs = [r for r in records.values() if project is None or r["project"] == project]
        jobs.sort(key=lambda r: (r["created_at"], r["id"]), reverse=True)
        return jobs[:limit]

    def events(self, job_id: str, *, after: int = 0) -> list[dict[str, Any]]:
        """The job's events with seq greater than *after*, in order."""
        path = self._done / f"{job_id}.events.jsonl"
        if not path.exists():
            return []
        events = []
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError as e:
                raise StateError(f"{path}:{lineno}: not JSON: {e}") from e
            violations = validate(EVENT_SCHEMA, event)
            if violations:
                raise StateError(f"{path}:{lineno}: {'; '.join(violations)}")
            if event["seq"] > after:
                events.append(event)
        return events


def _load_record(path: Path, job_id: str) -> dict[str, Any]:
    record = read_state(path)
    violations = validate(JOB_SCHEMA, record)
    if violations:
        raise StateError(f"Job record {path} is corrupt: {'; '.join(violations)}")
    if record["id"] != job_id:
        raise StateError(f"Job record {path} holds the id {record['id']}")
    return record
