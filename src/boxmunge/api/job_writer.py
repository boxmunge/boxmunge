# SPDX-License-Identifier: Apache-2.0
"""The write side of the job store: publish, claim and finish, each durable.

A job's record lives at state/jobs/queue/<id>.json while it is queued or
running, and moves to state/jobs/<id>.json once its terminal state is
written. Every step holds the job's lock (paths.job_lock) and syncs the file
and then every directory whose names it changed before it returns, so after
a power loss the record is never older than the last step that returned:

  publish   temp in jobs/ synced; link() into queue/; sync queue/; drop temp
  claim     temp synced; rename() over the queued record; sync queue/
  finish    as claim, with the terminal state; link() into jobs/; sync
            jobs/; unlink() from queue/; sync queue/

Temp files are written in state/jobs/ as .<id>.<token>.tmp, never in
queue/, so queue/ only ever holds <id>.json names. Every file is 0640 and
deploy-owned, so a root-run step never locks the deploy worker out.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from boxmunge.api.jobs import JOB_ID_PATTERN, JOB_SCHEMA, TERMINAL_STATES, worker_problems
from boxmunge.api.schema import validate
from boxmunge.api.timefmt import format_utc
from boxmunge.api.worker_identity import WorkerIdentity
from boxmunge.fileutil import durable_link, durable_unlink, exclusive_lock, fsync_dir
from boxmunge.fs_nofollow import fchown_deploy, mkdir_p_deploy, read_text_nofollow_or_none
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

FILE_MODE = 0o640
_JOB_ID_RE = re.compile(JOB_ID_PATTERN)


def new_record(job_id: str, action: str, params: dict[str, Any], principal_id: str,
               project: str | None, now: datetime) -> dict[str, Any]:
    """A queued job's record. params are stored as compact JSON text."""
    return {
        "id": _checked(job_id), "action": action, "principal": principal_id,
        "project": project, "state": "queued",
        "params": json.dumps(params, sort_keys=True, separators=(",", ":")),
        "worker": None, "created_at": format_utc(now), "started_at": None,
        "finished_at": None, "error": None, "result": None,
    }


def publish(paths: BoxPaths, record: dict[str, Any]) -> bool:
    """Make *record* a queued job. True once it is durably in queue/; False
    if a job with its id already exists (queued, running or finished)."""
    job_id = _checked(record["id"])
    violations = validate(JOB_SCHEMA, record) or worker_problems(record)
    if violations or record["state"] != "queued":
        raise ValueError(f"Not a queued job record ({job_id}): "
                         f"{'; '.join(violations) or 'state ' + repr(record['state'])}")
    queued, done = _queued(paths, job_id), _done(paths, job_id)
    with exclusive_lock(paths.job_lock(job_id)):
        if _exists(queued) or _exists(done):
            return False
        mkdir_p_deploy(paths.jobs_queue)
        tmp = _write_temp(paths, record)
        try:
            durable_link(tmp, queued)
        except FileExistsError:
            # Only a writer that ignored the job lock could have put it there.
            tmp.unlink()
            raise StateError(f"Job {job_id} appeared in {paths.jobs_queue} while it was "
                             f"being published, though its lock was held.") from None
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        durable_unlink(tmp)
    return True


def claim(paths: BoxPaths, job_id: str, identity: WorkerIdentity,
          now: datetime) -> dict[str, Any] | None:
    """Rewrite the queued record as running by *identity*, durably. None if
    the job is not in the queue or is not queued (another worker has it)."""
    queued = _queued(paths, _checked(job_id))
    with exclusive_lock(paths.job_lock(job_id)):
        record = _load(queued)
        if record is None or record["state"] != "queued":
            return None
        record = {**record, "state": "running", "worker": identity.as_record(),
                  "started_at": format_utc(now)}
        _replace(paths, queued, record)
    return record


def finish(paths: BoxPaths, job_id: str, *, state: str, error: dict[str, str] | None,
           result: dict[str, Any] | None, now: datetime) -> dict[str, Any]:
    """Write the job's terminal state over its queued record, then move it
    to state/jobs/<id>.json, each step synced before the next."""
    if state not in TERMINAL_STATES:
        raise ValueError(f"finish needs a terminal state, not {state!r}")
    queued = _queued(paths, _checked(job_id))
    with exclusive_lock(paths.job_lock(job_id)):
        record = _load(queued)
        if record is None:
            raise StateError(f"Job {job_id} is not in the queue ({queued}), so it cannot "
                             f"be finished.")
        if record["state"] in TERMINAL_STATES:
            raise StateError(f"Job {job_id} in {queued} is already {record['state']}; "
                             f"complete_finish moves it, finish never rewrites it.")
        record = {**record, "state": state, "error": error, "result": result,
                  "finished_at": format_utc(now)}
        _replace(paths, queued, record)
        _move_to_done(paths, job_id)
    return record


def complete_finish(paths: BoxPaths, job_id: str) -> None:
    """Finish the move of a terminal record a crash left in queue/."""
    with exclusive_lock(paths.job_lock(_checked(job_id))):
        _move_to_done(paths, job_id)


def _move_to_done(paths: BoxPaths, job_id: str) -> None:
    """link() queue/<id>.json into jobs/, then unlink() it from queue/. If a
    crash came between the two, jobs/<id>.json is already the same file and
    only the unlink is left. Holds the job lock (the caller's)."""
    queued, done = _queued(paths, job_id), _done(paths, job_id)
    if _exists(done):
        if not os.path.samefile(queued, done):
            raise StateError(f"{done} already holds a different record than {queued}. "
                             f"Compare the two and remove the wrong one.")
        durable_unlink(queued)
        return
    record = _load(queued)
    if record is None:
        raise StateError(f"Job {job_id} is not in the queue ({queued}).")
    if record["state"] not in TERMINAL_STATES:
        raise StateError(f"Job {job_id} in {queued} is still {record['state']}; only a "
                         f"finished job moves out of the queue.")
    durable_link(queued, done)
    durable_unlink(queued)


def _replace(paths: BoxPaths, target: Path, record: dict[str, Any]) -> None:
    """rename() a synced temp holding *record* over *target*, then sync
    target's directory."""
    _check_schema(record, str(target))
    tmp = _write_temp(paths, record)
    try:
        os.rename(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    fsync_dir(target.parent)


def _write_temp(paths: BoxPaths, record: dict[str, Any]) -> Path:
    """*record* in a synced, deploy-owned 0640 temp file in state/jobs/."""
    mkdir_p_deploy(paths.jobs_dir)
    fd, name = tempfile.mkstemp(dir=paths.jobs_dir, prefix=f".{record['id']}.", suffix=".tmp")
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(record, sort_keys=True).encode("utf-8"))
            f.flush()
            os.fchmod(f.fileno(), FILE_MODE)
            fchown_deploy(f.fileno(), name)
            os.fsync(f.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def _load(path: Path) -> dict[str, Any] | None:
    """The record at *path*, or None if nothing is there. A record that
    breaks JOB_SCHEMA is a StateError naming the file. Its result is not
    checked against its action here: the writer has no registry, and the
    reader (JobStore) checks it."""
    try:
        text = read_text_nofollow_or_none(path)
    except (OSError, UnicodeDecodeError) as e:
        raise StateError(f"Cannot read job record {path}: {e}") from e
    if text is None:
        return None
    try:
        record = json.loads(text)
    except ValueError as e:
        raise StateError(f"Job record {path} is not JSON: {e}") from e
    _check_schema(record, str(path))
    return record


def _check_schema(record: Any, where: str) -> None:
    # Without the registry a non-null result cannot be checked, so the
    # result is set aside here; JobStore checks it on every read.
    shape = {**record, "result": None} if isinstance(record, dict) else record
    violations = validate(JOB_SCHEMA, shape) or worker_problems(shape)
    if violations:
        raise StateError(f"Job record {where} is corrupt: {'; '.join(violations)}")


def _exists(path: Path) -> bool:
    """Whether anything is at the name, a link included (never followed)."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def _checked(job_id: str) -> str:
    if not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id):
        raise ValueError(f"{job_id!r} is not a job id (a ULID)")
    return job_id


def _queued(paths: BoxPaths, job_id: str) -> Path:
    return paths.jobs_queue / f"{job_id}.json"


def _done(paths: BoxPaths, job_id: str) -> Path:
    return paths.jobs_dir / f"{job_id}.json"
