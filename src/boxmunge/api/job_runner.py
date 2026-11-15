# SPDX-License-Identifier: Apache-2.0
"""The job runner: `boxmunge-server _job-runner`, run by boxmunge-jobs.service.

It runs every queued job, one `_run-job` worker process per job, and exits
once queue/ is empty and no worker of its own is left:

- Before starting anything, and again after every worker exits, it scans
  queue/ (recover_queue). A running job whose worker is gone is failed
  worker_lost and alerted with the action's way out, never run again; a
  finished record a crash left in queue/ is moved out; anything in queue/
  that is not a job record is set aside into jobs/rejected/ and alerted, so
  the path unit does not trigger on it forever.
- It starts queued jobs oldest first, at most MAX_CONCURRENT_JOBS at once
  and never two for one project (jobs with no project share one lane).
- A worker that exits EX_TEMPFAIL saw an upgrade hold the jobs gate and left
  its job queued for the new code. The runner then starts nothing more,
  waits for its other workers and exits 0, so boxmunge-jobs.path starts the
  service again on the code now installed.
- A worker that exits before claiming its job (a crash on start) leaves it
  queued; the runner fails it (nothing ran) instead of starting it again.

The unit's KillMode=control-group (systemd's default) is relied on: a
service stop signals every worker, and each fails its own job. So the
runner never exits on an error while workers run: it waits for them.
"""
from __future__ import annotations

import os
import queue as queue_mod
import re
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from boxmunge.api.audit import AuditError, AuditLog, audit_record
from boxmunge.api.job_events import EventLog
from boxmunge.api.job_recovery import (
    Recovery, advice_text, classify, lost_message, retry_command,
)
from boxmunge.api.job_worker import COMPONENT, EX_TEMPFAIL
from boxmunge.api.job_writer import (
    complete_finish, fail_unclaimed, finish, load_for_recovery,
)
from boxmunge.api.jobs import JOB_ID_PATTERN
from boxmunge.api.result import ErrorCode
from boxmunge.api.worker_identity import WorkerIdentity, is_alive
from boxmunge.fileutil import exclusive_lock, fsync_dir
from boxmunge.fs_nofollow import mkdir_p_deploy
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

MAX_CONCURRENT_JOBS = 4
RUNNER_POLL_SECONDS = 2
_RECORD_NAME = re.compile(rf"({JOB_ID_PATTERN})\.json")


class Child(Protocol):
    def wait(self) -> int: ...


def _spawn_worker(job_id: str) -> Child:
    """One `_run-job` worker; its output goes where the runner's does (the
    journal). `-m boxmunge` is the package's entry point (boxmunge.cli has
    no __main__ guard)."""
    return subprocess.Popen([sys.executable, "-m", "boxmunge", "_run-job", job_id])


@dataclass
class Scan:
    """What a queue scan left to act on: queued jobs oldest first, and the
    jobs whose live workers are running them."""
    queued: list[dict[str, Any]] = field(default_factory=list)
    running: list[dict[str, Any]] = field(default_factory=list)


def recover_queue(paths: BoxPaths, alive: Callable[[WorkerIdentity], bool]) -> Scan:
    """Apply the recovery table to every entry in queue/."""
    scan = Scan()
    try:
        entries = sorted(os.scandir(paths.jobs_queue), key=lambda e: e.name)
    except FileNotFoundError:
        return scan
    for entry in entries:
        match = _RECORD_NAME.fullmatch(entry.name)
        if match is None or not entry.is_file(follow_symlinks=False):
            _set_aside(paths, entry.name, "it is not a job record (<job id>.json)")
            continue
        job_id = match[1]
        try:
            record = load_for_recovery(paths, job_id)
        except StateError as e:
            events = paths.jobs_dir / f"{job_id}.events.jsonl"
            with exclusive_lock(paths.job_lock(job_id)):
                _set_aside(paths, entry.name, f"job {job_id}'s record cannot be read: {e}. "
                           f"Its events, if any, are in {events}")
            continue
        if record is None:
            continue  # it moved on since the listing
        recovery = classify(record, alive=alive)
        if recovery is Recovery.LOST:
            _mark_lost(paths, record)
        elif recovery is Recovery.COMPLETE_FINISH:
            complete_finish(paths, job_id)
            _recover_outcome_line(paths, record)
        elif recovery is Recovery.LEAVE:
            scan.running.append(record)
        else:
            scan.queued.append(record)
    scan.queued.sort(key=lambda r: (r["created_at"], r["id"]))
    return scan


def run_runner(paths: BoxPaths, *, spawn: Callable[[str], Child] = _spawn_worker,
               alive: Callable[[WorkerIdentity], bool] = is_alive) -> int:
    """Run the queue dry, then return 0. On an unexpected error it starts
    nothing more, waits for its running workers, then raises."""
    return _Runner(paths, spawn, alive).run()


class _Runner:
    def __init__(self, paths: BoxPaths, spawn: Callable[[str], Child],
                 alive: Callable[[WorkerIdentity], bool]) -> None:
        self._paths = paths
        self._spawn = spawn
        self._alive = alive
        self._children: dict[str, str | None] = {}  # job id -> its project (lane)
        self._exits: queue_mod.Queue[tuple[str, int]] = queue_mod.Queue()
        self._tempfailed = False

    def run(self) -> int:
        try:
            return self._loop()
        except Exception as e:
            # Exiting now would have systemd kill the running workers'
            # cgroup mid-job, so they finish first.
            log_error(COMPONENT, f"the job runner failed: {type(e).__name__}: {e}; it starts "
                      f"no more jobs and exits once its {len(self._children)} running "
                      f"worker(s) finish", self._paths,
                      detail={"traceback": traceback.format_exc()})
            while self._children:
                self._reap(timeout=None)
            raise

    def _loop(self) -> int:
        while True:
            scan = recover_queue(self._paths, self._alive)
            if not self._tempfailed:
                self._start(scan)
            foreign = any(r["id"] not in self._children for r in scan.running)
            if self._children:
                # Bounded, so a job published meanwhile on a free lane starts
                # without waiting for a long job to end.
                self._reap(timeout=RUNNER_POLL_SECONDS)
            elif self._tempfailed:
                return 0
            elif foreign:
                time.sleep(RUNNER_POLL_SECONDS)
            else:
                return 0  # nothing runs, so every queued job that may start has

    def _start(self, scan: Scan) -> None:
        busy = set(self._children.values()) | {r["project"] for r in scan.running}
        for record in scan.queued:
            if len(self._children) >= MAX_CONCURRENT_JOBS:
                return
            job_id, lane = record["id"], record["project"]
            if job_id in self._children or lane in busy:
                continue
            child = self._spawn(job_id)
            self._children[job_id] = lane
            busy.add(lane)
            threading.Thread(target=lambda j=job_id, c=child: self._exits.put((j, c.wait())),
                             name=f"wait-{job_id}", daemon=True).start()

    def _reap(self, timeout: float | None) -> None:
        """Wait for a worker to exit (up to *timeout*, then return to scan)."""
        try:
            job_id, code = self._exits.get(timeout=timeout)
        except queue_mod.Empty:
            return
        project = self._children.pop(job_id)
        if code == EX_TEMPFAIL:
            self._tempfailed = True
            return
        if code != 0:
            log_warning(COMPONENT, f"the worker for job {job_id} exited {code}", self._paths,
                        project=project)
            _fail_if_unclaimed(self._paths, job_id, code)


def _fail_if_unclaimed(paths: BoxPaths, job_id: str, code: int) -> None:
    """A worker that exited (not EX_TEMPFAIL) leaving its job queued died
    before its claim (a crash on start). Nothing ran, so the job is failed
    rather than started again: retrying a crash would loop."""
    try:
        record = load_for_recovery(paths, job_id)
    except StateError:
        return  # the next scan sets the unreadable record aside and alerts it
    if record is None or record["state"] != "queued":
        return
    message = (f"The worker for this job exited {code} before it started, so nothing was "
               f"run. Its output is in 'journalctl -u boxmunge-jobs'. Once that is fixed, "
               f"run the same call again: {retry_command(record)}")
    error = {"code": ErrorCode.FAILED.value, "message": message}
    if fail_unclaimed(paths, job_id, error=error, now=_now()) is None:
        return  # a worker claimed it after all
    _record_failure(paths, record, error, f"boxmunge: job {job_id} ({record['action']} "
                    f"{record['project']}) could not start")


def _mark_lost(paths: BoxPaths, record: dict[str, Any]) -> None:
    """Fail a job whose worker is gone, record and alert it; never re-run it.
    A job someone else finished first (another runner) is left to them."""
    job_id, action, project = record["id"], record["action"], record["project"]
    message = (f"{lost_message(record)} To recover: "
               f"{advice_text(paths, action, project)}.")
    error = {"code": "worker_lost", "message": message}
    try:
        finish(paths, job_id, state="failed", error=error, result=None, now=_now())
    except StateError:
        now = load_for_recovery(paths, job_id)
        if now is not None and (now["state"] == "running" or now["error"] == error):
            raise  # not someone else's finish: this one failed part way
        log_warning(COMPONENT, f"job {job_id} was lost, but was finished elsewhere before "
                    f"the runner could fail it", paths, project=project)
        return
    _record_failure(paths, record, error, f"boxmunge: job {job_id} ({action} {project}) "
                    f"was cut off")


def _record_failure(paths: BoxPaths, record: dict[str, Any], error: dict[str, str],
                    title: str) -> None:
    """The events, outcome audit line and alert of a job the runner failed."""
    _write_failure_events(paths, record, error["message"])
    _audit(paths, record, "failed", error)
    notify(paths, title, error["message"], component=COMPONENT, project=record["project"],
           priority=1)


def _write_failure_events(paths: BoxPaths, record: dict[str, Any], message: str) -> None:
    """Append the failure to the job's events. A worker killed mid-write
    leaves a torn last line, which EventLog refuses (StateError): the record
    is already failed, so that is logged, not raised."""
    job_id, project = record["id"], record["project"]
    path = paths.jobs_dir / f"{job_id}.events.jsonl"
    try:
        events = EventLog(paths, job_id)
    except (StateError, OSError) as e:
        log_error(COMPONENT, f"job {job_id} was failed, but its events {path} cannot be "
                  f"appended ({e}); the job record holds the outcome.", paths, project=project)
        return
    try:
        events.log(message)
        events.state("failed")
    except OSError as e:
        log_error(COMPONENT, f"job {job_id} was failed, but writing to its events {path} "
                  f"failed ({e}); the job record holds the outcome.", paths, project=project)
    finally:
        events.close()


def _recover_outcome_line(paths: BoxPaths, record: dict[str, Any]) -> None:
    """A finish cut off mid-move: its worker audits strictly after the move
    (and finish holds the job lock across it), so it never wrote the
    outcome line. Write it from the record, once."""
    _audit(paths, record, record["state"], record["error"])
    log_operation(COMPONENT, f"job {record['id']}: its worker died while moving the finished "
                  f"record out of the queue; the move was completed and the outcome audit "
                  f"line ({record['state']}) recovered from the record", paths,
                  project=record["project"])


def _audit(paths: BoxPaths, record: dict[str, Any], outcome: str,
           error: dict[str, str] | None) -> None:
    """The outcome audit line the worker could not write. params are left
    out: the runner loads no registry to redact them, and the job's
    accepted line already carries them."""
    code = None if error is None else error["code"]
    line = audit_record(record["principal"], record["action"], outcome, code=code,
                        message=None if error is None else error["message"], job=record["id"])
    try:
        AuditLog(paths.audit_log, create=False).append(line)
    except AuditError as e:
        shown = outcome if code is None else f"{outcome}, {code}"
        log_error("audit", f"could not record the outcome of {record['action']} (job "
                  f"{record['id']}): {e}", paths, detail={"outcome": outcome})
        notify(paths, "boxmunge: audit log write failed",
               f"The outcome ({shown}) of {record['action']} by "
               f"{record['principal']} (job {record['id']}) was not recorded: {e}. The job "
               f"record keeps it.", component="audit", priority=1)


def _set_aside(paths: BoxPaths, name: str, why: str) -> None:
    """Rename queue/<name> (never followed) into jobs/rejected/ and alert."""
    stamp = _now().strftime("%Y%m%dT%H%M%S%fZ")
    source, target = paths.jobs_queue / name, paths.jobs_rejected / f"{name}.{stamp}"
    mkdir_p_deploy(paths.jobs_rejected)
    os.rename(source, target)
    fsync_dir(paths.jobs_queue)
    fsync_dir(paths.jobs_rejected)
    message = (f"{source} was set aside as {target}: {why}. No job was run from it. "
               f"Inspect it, then delete it.")
    log_error(COMPONENT, message, paths)
    notify(paths, "boxmunge: unexpected entry in the job queue", message,
           component=COMPONENT, priority=1)


def _now() -> datetime:
    return datetime.now(timezone.utc)
