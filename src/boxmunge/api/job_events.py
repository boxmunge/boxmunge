# SPDX-License-Identifier: Apache-2.0
"""The writer of a job's event log, state/jobs/<id>.events.jsonl.

One JSON object per line, each checked against EVENT_SCHEMA before it is
written, numbered by seq from 1. The worker, its output capture and the
core's step reporting all write through one EventLog, from several threads,
so numbering and appending happen under one lock. deploy can write
state/jobs/, and the worker may run as root, so the file is opened without
following a link and handed to deploy.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.api.jobs import EVENT_SCHEMA
from boxmunge.api.schema import validate
from boxmunge.api.timefmt import format_utc
from boxmunge.fs_nofollow import fchown_deploy, open_regular_nofollow, read_text_nofollow_or_none
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

MAX_EVENT_MESSAGE = 4000


class EventLog:
    def __init__(self, paths: BoxPaths, job_id: str) -> None:
        self._path = paths.jobs_dir / f"{job_id}.events.jsonl"
        self._seq = _last_seq(self._path)
        self._fd = open_regular_nofollow(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                                         0o640)
        fchown_deploy(self._fd, str(self._path))
        self._lock = threading.Lock()

    def log(self, message: str) -> int:
        return self._write({"type": "log", "message": message})

    def step(self, step: str, status: str, message: str | None = None) -> int:
        event: dict[str, Any] = {"type": "step", "step": step, "status": status}
        if message is not None:
            event["message"] = message
        return self._write(event)

    def state(self, state: str) -> int:
        return self._write({"type": "state", "state": state})

    def close(self) -> None:
        with self._lock:
            try:
                os.fsync(self._fd)
            finally:
                os.close(self._fd)

    def _write(self, fields: dict[str, Any]) -> int:
        """Append one event; its seq. An event outside EVENT_SCHEMA is a
        bug in the caller and raises ValueError, unwritten."""
        if "message" in fields:
            fields["message"] = _cut(fields["message"])
        with self._lock:
            event = {"seq": self._seq + 1,
                     "ts": format_utc(datetime.now(timezone.utc)), **fields}
            violations = validate(EVENT_SCHEMA, event)
            if violations:
                raise ValueError(f"Refusing to write an invalid event to {self._path}: "
                                 f"{'; '.join(violations)}")
            line = (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8")
            written = os.write(self._fd, line)
            if written != len(line):
                raise OSError(f"Short write to {self._path}: {written} of {len(line)} bytes")
            self._seq += 1
            return self._seq


def _cut(message: str) -> str:
    extra = len(message) - MAX_EVENT_MESSAGE
    if extra <= 0:
        return message
    return f"{message[:MAX_EVENT_MESSAGE]}…({extra} more characters)"


def _last_seq(path: Path) -> int:
    """The seq of the file's last event, 0 for an empty file. A last line
    that is not a valid event is corrupt (StateError naming the file):
    numbering past it could repeat or skip a seq."""
    try:
        text = read_text_nofollow_or_none(path)
    except (OSError, UnicodeDecodeError) as e:
        raise StateError(f"Cannot read job events {path}: {e}") from e
    numbered = [(n, line) for n, line in enumerate((text or "").splitlines(), start=1)
                if line.strip()]
    if not numbered:
        return 0
    lineno, line = numbered[-1]
    try:
        event = json.loads(line)
    except ValueError as e:
        raise StateError(f"{path}:{lineno}: not JSON: {e}") from e
    violations = validate(EVENT_SCHEMA, event)
    if violations:
        raise StateError(f"{path}:{lineno}: {'; '.join(violations)}")
    return event["seq"]
