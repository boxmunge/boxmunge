# SPDX-License-Identifier: Apache-2.0
"""The write side of the job store: publish, claim and finish, each durable.

A job's record lives at state/jobs/queue/<id>.json while it is queued or
running, and moves to state/jobs/<id>.json once its terminal state is
written. Every step holds the job's lock (paths.job_lock) and syncs the file
and then every directory whose names it changed before it returns, so after
a power loss the record is never older than the last step that returned:

  publish   temp in jobs/ synced; link() into queue/; sync queue/; drop temp
  claim     temp synced; rename() over the queued record; sync queue/, jobs/
  finish    as claim, with the terminal state; link() into jobs/; sync
            jobs/; unlink() from queue/; sync queue/

A publish that raises after its link removes the queued name again before
it returns, so a publish that raised queued nothing (only a crash, which
runs no cleanup, leaves a queued job behind, and that job runs).

Temp files are written in state/jobs/ as .<id>.<token>.tmp, never in
queue/, so queue/ only ever holds <id>.json names. Every file is 0640 and
deploy-owned, so a root-run step never locks the deploy worker out.

With the job's lock held, any .<id>.*.tmp is left over from a step that
crashed, so every step first removes them. That also clears the second link
a publish that crashed before dropping its temp leaves on the queued
record. A finish that crashed between its link and unlink leaves one file
under both names, which jobs.read_record_text accepts and _move_to_done
completes. The job runner's queue scan calls load_for_recovery.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from boxmunge.api.jobs import (
    JOB_ID_PATTERN, JOB_SCHEMA, TERMINAL_STATES, is_mid_move, read_record_text, worker_problems,
)
from boxmunge.api.schema import ResultSchemas, validate
from boxmunge.api.timefmt import format_utc
from boxmunge.api.worker_identity import WorkerIdentity
from boxmunge.fileutil import durable_link, durable_unlink, exclusive_lock, fsync_dir
from boxmunge.fs_nofollow import fchown_deploy, mkdir_p_deploy
from boxmunge.log import log_error
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
        _sweep_temps(paths, job_id)
        if _exists(queued) or _exists(done):
            return False
        mkdir_p_deploy(paths.jobs_queue)
        tmp = _write_temp(paths, record)
        try:
            os.link(tmp, queued)
        except FileExistsError:
            tmp.unlink()
            raise StateError(
                f"{queued} appeared while job {job_id} was being published under its lock, "
                f"so something wrote it without the lock. Inspect {queued}; if it is not "
                f"this job's record, remove it and make the call again.") from None
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        try:
            fsync_dir(paths.jobs_queue)
            durable_unlink(tmp)
        except BaseException:
            _withdraw(paths, queued, tmp)
            raise
    return True


def _withdraw(paths: BoxPaths, queued: Path, tmp: Path) -> None:
    """Undo a publish that failed after its link, so a publish that raises
    has queued nothing and the caller may report the job as not queued.
    Holds the job lock (publish's), so no worker has claimed the record."""
    try:
        os.unlink(queued)
    except FileNotFoundError:
        pass
    except OSError as e:
        raise StateError(
            f"Publishing job {queued.stem} failed after {queued} was written, and it could "
            f"not be removed again ({e}), so the job is queued and will run. Do not make "
            f"the call again; follow the job with the job.get action (id {queued.stem}).") from e
    tmp.unlink(missing_ok=True)
    try:
        fsync_dir(queued.parent)
    except OSError as e:
        log_error("jobs", f"Withdrew {queued} after a failed publish, but could not sync "
                  f"{queued.parent}: {e}", paths)


def claim(paths: BoxPaths, job_id: str, identity: WorkerIdentity,
          now: datetime) -> dict[str, Any] | None:
    """Rewrite the queued record as running by *identity*, durably. None if
    the job is not in the queue or is not queued (another worker has it)."""
    queued = _queued(paths, _checked(job_id))
    with exclusive_lock(paths.job_lock(job_id)):
        _sweep_temps(paths, job_id)
        record = _load(paths, job_id, queued)
        if record is None or record["state"] != "queued":
            return None
        record = {**record, "state": "running", "worker": identity.as_record(),
                  "started_at": format_utc(now)}
        _replace(paths, queued, record)
    return record


def finish(paths: BoxPaths, job_id: str, *, state: str, error: dict[str, str] | None,
           result: dict[str, Any] | None, now: datetime,
           result_schemas: ResultSchemas | None = None) -> dict[str, Any]:
    """Write the running job's terminal state over its queued record, then
    move it to state/jobs/<id>.json, each step synced before the next.

    A failed job has an error and no result; a succeeded one has no error.
    A non-null result is checked against its action's result schema, which
    *result_schemas* resolves, so a bad result fails here, not on a read.
    """
    _check_outcome(state, error, result, result_schemas is not None)
    queued = _queued(paths, _checked(job_id))
    with exclusive_lock(paths.job_lock(job_id)):
        _sweep_temps(paths, job_id)
        record = _load(paths, job_id, queued)
        if record is None or record["state"] != "running":
            found = "nothing" if record is None else f"a {record['state']} record"
            raise StateError(f"Job {job_id} cannot be finished: only a running job can, and "
                             f"{queued} holds {found}.")
        record = {**record, "state": state, "error": error, "result": result,
                  "finished_at": format_utc(now)}
        if result_schemas is not None:
            _check_result(record, result_schemas)
        _replace(paths, queued, record)
        _move_to_done(paths, job_id)
    return record


def complete_finish(paths: BoxPaths, job_id: str) -> None:
    """Finish the move of a terminal record a crash left in queue/."""
    with exclusive_lock(paths.job_lock(_checked(job_id))):
        _sweep_temps(paths, job_id)
        _move_to_done(paths, job_id)


def load_for_recovery(paths: BoxPaths, job_id: str) -> dict[str, Any] | None:
    """The record of *job_id* in queue/, after clearing what a crashed step
    left (its temps), or None if the job is not in the queue. A terminal
    record returned here is one whose finish crashed: complete_finish it."""
    queued = _queued(paths, _checked(job_id))
    with exclusive_lock(paths.job_lock(job_id)):
        _sweep_temps(paths, job_id)
        return _load(paths, job_id, queued)


def _check_outcome(state: str, error: dict[str, str] | None, result: dict[str, Any] | None,
                   checkable: bool) -> None:
    if state not in TERMINAL_STATES:
        raise ValueError(f"finish needs a terminal state, not {state!r}")
    if state == "failed" and (error is None or result is not None):
        raise ValueError("A failed job needs an error and no result.")
    if state == "succeeded" and error is not None:
        raise ValueError("A succeeded job has no error.")
    if result is not None and not checkable:
        raise ValueError("A job's result can only be written with result_schemas, which "
                         "check it against its action's result schema.")


def _check_result(record: dict[str, Any], result_schemas: ResultSchemas) -> None:
    if record["result"] is not None and result_schemas(record["action"]) is None:
        raise ValueError(f"Action {record['action']} has no registered result schema, so its "
                         f"result cannot be written.")
    violations = validate(JOB_SCHEMA, record, result_schemas=result_schemas)
    if violations:
        raise ValueError(f"Job {record['id']}'s result breaks its schema: "
                         f"{'; '.join(violations)}")


def _move_to_done(paths: BoxPaths, job_id: str) -> None:
    """link() queue/<id>.json into jobs/, then unlink() it from queue/. If a
    crash came between the two, jobs/<id>.json is already the same file and
    only the unlink is left. Holds the job lock (the caller's)."""
    queued, done = _queued(paths, job_id), _done(paths, job_id)
    if is_mid_move(paths, job_id):
        durable_unlink(queued)
        return
    if _exists(done):
        raise StateError(f"{done} already holds a different record than {queued}, so job "
                         f"{job_id} cannot be moved out of the queue. Compare the two files "
                         f"and remove the one that is not the job's finished record.")
    record = _load(paths, job_id, queued)
    if record is None:
        raise StateError(f"Job {job_id} is not in the queue ({queued}).")
    if record["state"] not in TERMINAL_STATES:
        raise StateError(f"Job {job_id} in {queued} is still {record['state']}; only a "
                         f"finished job moves out of the queue.")
    durable_link(queued, done)
    durable_unlink(queued)


def _sweep_temps(paths: BoxPaths, job_id: str) -> None:
    """Remove the job's temps. Called with its lock held, when no step of
    this job is running, so every one is left over from a crash."""
    for tmp in sorted(paths.jobs_dir.glob(f".{job_id}.*.tmp")):
        durable_unlink(tmp)


def _replace(paths: BoxPaths, target: Path, record: dict[str, Any]) -> None:
    """rename() a synced temp holding *record* over *target*, then sync
    target's directory and the temp's (state/jobs/, which lost a name)."""
    _check_schema(record, str(target))
    tmp = _write_temp(paths, record)
    try:
        os.rename(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    fsync_dir(target.parent)
    fsync_dir(paths.jobs_dir)


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


def _load(paths: BoxPaths, job_id: str, path: Path) -> dict[str, Any] | None:
    """Job *job_id*'s record at *path*, or None if nothing is there. A record
    that breaks JOB_SCHEMA, or holds another id, is a StateError naming the
    file. Its result is not checked against its action here (the writer has
    no registry); JobStore checks it on every read."""
    try:
        text = read_record_text(paths, job_id, path)
    except UnicodeDecodeError as e:
        raise StateError(f"Cannot read job record {path}: {e}") from e
    if text is None:
        return None
    try:
        record = json.loads(text)
    except ValueError as e:
        raise StateError(f"Job record {path} is not JSON: {e}") from e
    except RecursionError as e:
        raise StateError(f"Job record {path} is nested too deeply") from e
    _check_schema(record, str(path))
    if record["id"] != job_id:
        raise StateError(f"Job record {path} holds the id {record['id']}")
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
