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
from boxmunge.api.timefmt import NULLABLE_TIMESTAMP, TIMESTAMP
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

JOB_ID_PATTERN = "[0-9A-HJKMNP-TV-Z]{26}"
_JOB_ID_RE = re.compile(JOB_ID_PATTERN)
JOB_STATES = ("queued", "running", "succeeded", "failed")
TERMINAL_STATES = frozenset({"succeeded", "failed"})
EVENT_TYPES = ("log", "step", "state")
STEP_STATUSES = ("started", "succeeded", "failed")

JOB_SCHEMA = obj({
    "id": {"type": "string", "pattern": JOB_ID_PATTERN},
    "action": STRING,
    "principal": STRING,
    "project": NULLABLE_STRING,
    "state": enum(*JOB_STATES),
    "created_at": TIMESTAMP,
    "started_at": NULLABLE_TIMESTAMP,
    "finished_at": NULLABLE_TIMESTAMP,
    "error": nullable(obj({"code": STRING, "message": STRING})),
    # The action's result once the job has succeeded, in the shape of that
    # action's catalog result schema. No action runs as a job in this
    # release, so it is always null; the job runner widens the type.
    "result": {"type": "null",
               "description": "The action's result once the job succeeds; null until then."},
})

EVENT_SCHEMA = obj({
    "seq": {"type": "integer", "minimum": 1},
    "ts": TIMESTAMP,
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
        found = None
        for directory in (self._queue, self._done):
            record = _load_record(directory / f"{job_id}.json", job_id)
            if record is not None:
                found = _prefer(found, record)
        return found

    def recent(self, *, project: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Jobs newest first, optionally for one project.

        queue/ is scanned before jobs/: finishing a job links its record
        into jobs/ before unlinking it from queue/, so a job that moves
        while we look is found in one place or the other, never missed. A
        file that vanishes between listing and reading has moved on.
        """
        records: dict[str, dict[str, Any]] = {}
        for directory in (self._queue, self._done):
            if not directory.is_dir():
                continue
            for path in directory.glob("*.json"):
                if not _JOB_ID_RE.fullmatch(path.stem):
                    continue
                record = _load_record(path, path.stem)
                if record is not None:
                    records[path.stem] = _prefer(records.get(path.stem), record)
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


def _prefer(current: dict[str, Any] | None, other: dict[str, Any]) -> dict[str, Any]:
    """Of two copies of one job, the terminal one: while a job is being
    finished its record can briefly exist in both directories."""
    if current is None or (other["state"] in TERMINAL_STATES
                           and current["state"] not in TERMINAL_STATES):
        return other
    return current


def _load_record(path: Path, job_id: str) -> dict[str, Any] | None:
    """The record at *path*, or None if there is none there (any more)."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise StateError(f"Cannot read job record {path}: {e}") from e
    try:
        record = json.loads(text)
    except ValueError as e:
        raise StateError(f"Job record {path} is not JSON: {e}") from e
    violations = validate(JOB_SCHEMA, record)
    if violations:
        raise StateError(f"Job record {path} is corrupt: {'; '.join(violations)}")
    if record["id"] != job_id:
        raise StateError(f"Job record {path} holds the id {record['id']}")
    return record
