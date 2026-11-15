# SPDX-License-Identifier: Apache-2.0
"""Job records on disk, and the read side the jobs.* actions use.

Layout (job_writer writes the records, the job runner the events):
  state/jobs/queue/<id>.json     every unfinished job (queued or running)
  state/jobs/<id>.json           finished jobs (succeeded or failed)
  state/jobs/<id>.events.jsonl   the job's events, one JSON object per line
  state/jobs/<id>.lock           held by every write of the record, and by
                                 every read of it here

JOB_SCHEMA and EVENT_SCHEMA are the formats every writer must produce. A
record or event line that breaks them is reported as corrupt (StateError),
never skipped.
"""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxmunge.api.schema import (
    NULLABLE_STRING, RESULT_OF_ACTION, STRING, ResultSchemas, enum, nullable, obj, validate,
)
from boxmunge.api.timefmt import NULLABLE_TIMESTAMP, TIMESTAMP
from boxmunge.api.worker_identity import PROC, WORKER_SCHEMA, WorkerIdentity, is_alive
from boxmunge.fileutil import shared_lock
from boxmunge.fs_nofollow import read_text_nofollow_or_none
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
    # The call's params as compact JSON text (sorted keys, no spaces): the
    # closed schema has no open object, so they are stored as a string.
    "params": STRING,
    # Who claimed the job: null while queued, set from the claim on.
    "worker": nullable(WORKER_SCHEMA),
    "created_at": TIMESTAMP,
    "started_at": NULLABLE_TIMESTAMP,
    "finished_at": NULLABLE_TIMESTAMP,
    "error": nullable(obj({"code": STRING, "message": STRING})),
    # Null until the job has succeeded, then the action's result in the
    # shape of that action's catalog result schema.
    "result": RESULT_OF_ACTION,
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


@dataclass(frozen=True)
class JobListing:
    """Jobs (newest first from recent(), oldest first from unfinished()),
    and the records that could not be read: each {"id", "problem"}, the
    problem naming the file."""

    jobs: list[dict[str, Any]]
    unreadable: list[dict[str, str]]


class JobStore:
    """*result_schemas* resolves an action to its result schema, so a
    non-null result is checked against the action that produced it.

    A running job whose worker is gone (see worker_identity.is_alive, which
    reads *proc*) is reported as failed with the error worker_lost. That is
    presentation only: the record on disk is left alone, and the job runner
    is what writes the failure.
    """

    def __init__(self, paths: BoxPaths, *, result_schemas: ResultSchemas,
                 proc: Path = PROC) -> None:
        self._paths = paths
        self._done = paths.jobs_dir
        self._queue = paths.jobs_queue
        self._result_schemas = result_schemas
        self._proc = proc

    def get(self, job_id: str) -> dict[str, Any] | None:
        """The job's record, or None if there is no such job. A record that
        cannot be read raises StateError naming the file."""
        found = None
        for directory in (self._queue, self._done):
            record = self._load(directory / f"{job_id}.json", job_id)
            if record is not None:
                found = _prefer(found, record)
        return None if found is None else self._presented(found)

    def recent(self, *, project: str | None = None, limit: int = 50) -> JobListing:
        """Jobs newest first, optionally for one project.

        queue/ is scanned before jobs/: finishing a job links its record
        into jobs/ before unlinking it from queue/, so a job that moves
        while we look is found in one place or the other, never missed. A
        file that vanishes between listing and reading has moved on. A
        record that cannot be read is listed as unreadable (its project is
        unknowable, so whatever the filter) and never hides the others.
        """
        records, unreadable = self._scan((self._queue, self._done))
        jobs = [self._presented(r) for r in records.values()
                if project is None or r["project"] == project]
        jobs.sort(key=lambda r: (r["created_at"], r["id"]), reverse=True)
        return JobListing(jobs=jobs[:limit], unreadable=unreadable)

    def unfinished(self) -> JobListing:
        """The queued and running jobs in queue/, oldest first, and the
        records there that cannot be read. A finished record still in queue/
        (its finish was cut short, and the runner completes the move) is not
        unfinished."""
        records, unreadable = self._scan((self._queue,))
        jobs = [self._presented(r) for r in records.values()
                if r["state"] not in TERMINAL_STATES]
        jobs.sort(key=lambda r: (r["created_at"], r["id"]))
        return JobListing(jobs=jobs, unreadable=unreadable)

    def _scan(self, directories: tuple[Path, ...]) -> tuple[dict[str, dict[str, Any]],
                                                            list[dict[str, str]]]:
        """The records in *directories*, by id, and those that could not be
        read (see recent())."""
        records: dict[str, dict[str, Any]] = {}
        problems: dict[str, str] = {}
        for directory in directories:
            if not directory.is_dir():
                continue
            for path in directory.glob("*.json"):
                if not _JOB_ID_RE.fullmatch(path.stem):
                    continue
                try:
                    record = self._load(path, path.stem)
                except StateError as e:
                    problems.setdefault(path.stem, str(e))
                    continue
                if record is not None:
                    records[path.stem] = _prefer(records.get(path.stem), record)
        unreadable = [{"id": job_id, "problem": problem}
                      for job_id, problem in sorted(problems.items()) if job_id not in records]
        return records, unreadable

    def events(self, job_id: str, *, after: int = 0) -> list[dict[str, Any]]:
        """The job's events with seq greater than *after*, in order."""
        path = self._done / f"{job_id}.events.jsonl"
        text = _read(path, "job events")
        if text is None:
            return []
        events = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                violations = validate(EVENT_SCHEMA, event)
            except ValueError as e:
                raise StateError(f"{path}:{lineno}: not JSON: {e}") from e
            except RecursionError as e:
                raise StateError(f"{path}:{lineno}: nested too deeply") from e
            if violations:
                raise StateError(f"{path}:{lineno}: {'; '.join(violations)}")
            if event["seq"] > after:
                events.append(event)
        return events

    def _presented(self, record: dict[str, Any]) -> dict[str, Any]:
        """*record*, or, if it is running and its worker is gone, the failed
        record the runner will write for it."""
        if record["state"] != "running":
            return record
        worker = WorkerIdentity.from_record(record["worker"])
        if is_alive(worker, self._proc):
            return record
        return {**record, "state": "failed", "error": {
            "code": "worker_lost",
            "message": (f"The worker running this job (pid {worker.pid}) is gone: it exited "
                        f"or the box restarted before the job finished. The job is not re-run, "
                        f"because a half-done {record['action']} must not repeat itself; check "
                        f"what it changed before starting it again."),
        }}

    def _load(self, path: Path, job_id: str) -> dict[str, Any] | None:
        """The record at *path*, or None if there is none there (any more).

        Read under a shared hold of the job's lock, so never in the middle
        of a job_writer step (publish and finish briefly give the record a
        second hard link, which the no-follow read refuses). Nothing at the
        name means no record, and no lock file is created for it.
        """
        try:
            os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError as e:
            raise StateError(f"Cannot read job record {path}: {e}") from e
        with shared_lock(self._paths.job_lock(job_id)):
            text = read_record_text(self._paths, job_id, path)
        if text is None:
            return None
        try:
            record = json.loads(text)
            violations = validate(JOB_SCHEMA, record, result_schemas=self._result_schemas)
        except ValueError as e:
            raise StateError(f"Job record {path} is not JSON: {e}") from e
        except RecursionError as e:
            raise StateError(f"Job record {path} is nested too deeply") from e
        action = record.get("action") if isinstance(record, dict) else None
        if (isinstance(action, str) and record.get("result") is not None
                and self._result_schemas(action) is None):
            raise StateError(f"Job record {path}: action {action} is no longer registered, "
                             f"so its result cannot be checked")
        if not violations:
            violations = worker_problems(record)
        if violations:
            raise StateError(f"Job record {path} is corrupt: {'; '.join(violations)}")
        if record["id"] != job_id:
            raise StateError(f"Job record {path} holds the id {record['id']}")
        return record


def worker_problems(record: dict[str, Any]) -> list[str]:
    """A queued job has no worker yet; a running one must name its worker."""
    if record["state"] == "queued" and record["worker"] is not None:
        return ["$.worker: the job is queued but names a worker"]
    if record["state"] == "running" and record["worker"] is None:
        return ["$.worker: the job is running but names no worker"]
    return []


def read_record_text(paths: BoxPaths, job_id: str, path: Path) -> str | None:
    """The text of job *job_id*'s record at *path* (in queue/ or jobs/), or
    None if nothing is there. The caller holds the job's lock.

    A finish that crashed between its link into jobs/ and its unlink from
    queue/ leaves one file under both names, with two links. That record is
    read, from either name; any other extra link is refused.
    """
    return _read(path, "job record", links=2 if is_mid_move(paths, job_id) else 1)


def is_mid_move(paths: BoxPaths, job_id: str) -> bool:
    """Whether queue/<id>.json and jobs/<id>.json are one regular file. With
    exactly two links (read_record_text requires that) those are its only
    names, so it is the job's own record, never a file linked in from
    elsewhere."""
    try:
        queued = os.lstat(paths.jobs_queue / f"{job_id}.json")
        done = os.lstat(paths.jobs_dir / f"{job_id}.json")
    except FileNotFoundError:
        return False
    except OSError as e:
        raise StateError(f"Cannot read job record {job_id} in {paths.jobs_dir}: {e}") from e
    return stat.S_ISREG(queued.st_mode) and (queued.st_dev, queued.st_ino) == (
        done.st_dev, done.st_ino)


def _read(path: Path, what: str, *, links: int = 1) -> str | None:
    """The file's text, or None if nothing is at the name. deploy writes
    state/jobs/, so a link, a FIFO or an oversized file there is refused
    (StateError naming the file), never followed or waited on."""
    try:
        return read_text_nofollow_or_none(path, links=links)
    except (OSError, UnicodeDecodeError) as e:
        raise StateError(f"Cannot read {what} {path}: {e}") from e


def _prefer(current: dict[str, Any] | None, other: dict[str, Any]) -> dict[str, Any]:
    """Of two copies of one job, the terminal one: while a job is being
    finished its record can briefly exist in both directories."""
    if current is None or (other["state"] in TERMINAL_STATES
                           and current["state"] not in TERMINAL_STATES):
        return other
    return current
