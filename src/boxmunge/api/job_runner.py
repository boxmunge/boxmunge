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
"""
from __future__ import annotations

import os
import queue as queue_mod
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from boxmunge.api.audit import AuditError, AuditLog, audit_record
from boxmunge.api.job_events import EventLog
from boxmunge.api.job_recovery import Recovery, classify, lost_message, recovery_advice
from boxmunge.api.job_worker import COMPONENT, EX_TEMPFAIL
from boxmunge.api.job_writer import complete_finish, finish, load_for_recovery
from boxmunge.api.jobs import JOB_ID_PATTERN
from boxmunge.api.worker_identity import WorkerIdentity, is_alive
from boxmunge.fileutil import exclusive_lock, fsync_dir
from boxmunge.fs_nofollow import mkdir_p_deploy
from boxmunge.log import log_error, log_warning
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
            with exclusive_lock(paths.job_lock(job_id)):
                _set_aside(paths, entry.name, f"job {job_id}'s record cannot be read: {e}")
            continue
        if record is None:
            continue  # it moved on since the listing
        recovery = classify(record, alive=alive)
        if recovery is Recovery.LOST:
            _mark_lost(paths, record)
        elif recovery is Recovery.COMPLETE_FINISH:
            complete_finish(paths, job_id)
        elif recovery is Recovery.LEAVE:
            scan.running.append(record)
        else:
            scan.queued.append(record)
    scan.queued.sort(key=lambda r: (r["created_at"], r["id"]))
    return scan


def run_runner(paths: BoxPaths, *, spawn: Callable[[str], Child] = _spawn_worker,
               alive: Callable[[WorkerIdentity], bool] = is_alive) -> int:
    """Run the queue dry: 0, or 1 when a job is left queued that its worker
    exited without running (alerted; not started again by this run)."""
    return _Runner(paths, spawn, alive).run()


class _Runner:
    def __init__(self, paths: BoxPaths, spawn: Callable[[str], Child],
                 alive: Callable[[WorkerIdentity], bool]) -> None:
        self._paths = paths
        self._spawn = spawn
        self._alive = alive
        self._children: dict[str, str | None] = {}  # job id -> its project (lane)
        self._exits: queue_mod.Queue[tuple[str, int]] = queue_mod.Queue()
        self._unrunnable: set[str] = set()
        self._tempfailed = False

    def run(self) -> int:
        while True:
            scan = recover_queue(self._paths, self._alive)
            if not self._tempfailed:
                self._start(scan)
            foreign = any(r["id"] not in self._children for r in scan.running)
            if self._children:
                self._reap(timeout=RUNNER_POLL_SECONDS if foreign else None)
            elif self._tempfailed:
                return 0
            elif foreign:
                time.sleep(RUNNER_POLL_SECONDS)
            else:
                # Nothing runs, so every queued job that may start has.
                return 1 if self._unrunnable else 0

    def _start(self, scan: Scan) -> None:
        busy = set(self._children.values()) | {r["project"] for r in scan.running}
        for record in scan.queued:
            if len(self._children) >= MAX_CONCURRENT_JOBS:
                return
            job_id, lane = record["id"], record["project"]
            if job_id in self._children or job_id in self._unrunnable or lane in busy:
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
        try:
            record = load_for_recovery(self._paths, job_id)
        except StateError:
            return  # the next scan sets the unreadable record aside and alerts it
        if record is not None and record["state"] == "queued":
            self._unrunnable.add(job_id)
            message = (f"The worker for job {job_id} ({record['action']} {project}) exited "
                       f"{code} without running it, so the job is still queued. The runner "
                       f"will not start it again until it restarts; the worker's error is "
                       f"in 'journalctl -u boxmunge-jobs'.")
            log_error(COMPONENT, message, self._paths, project=project)
            notify(self._paths, f"boxmunge: job {job_id} could not start", message,
                   component=COMPONENT, project=project, priority=1)


def _mark_lost(paths: BoxPaths, record: dict[str, Any]) -> None:
    """Fail a job whose worker is gone, record and alert it; never re-run it."""
    job_id, action, project = record["id"], record["action"], record["project"]
    message = lost_message(record)
    error = {"code": "worker_lost", "message": message}
    finish(paths, job_id, state="failed", error=error, result=None, now=_now())
    _write_lost_events(paths, job_id, message, project)
    _audit(paths, record, error)
    notify(paths, f"boxmunge: job {job_id} ({action} {project}) was cut off",
           f"{message} To recover: {_advice(paths, action, project)}.",
           component=COMPONENT, project=project, priority=1)


def _write_lost_events(paths: BoxPaths, job_id: str, message: str,
                       project: str | None) -> None:
    """Append the loss to the job's events. A worker killed mid-write leaves
    a torn last line, which EventLog refuses (StateError): the record is
    already failed, so that is logged, not raised."""
    path = paths.jobs_dir / f"{job_id}.events.jsonl"
    try:
        events = EventLog(paths, job_id)
    except (StateError, OSError) as e:
        log_error(COMPONENT, f"job {job_id} was failed worker_lost, but its events "
                  f"{path} cannot be appended ({e}); the job record holds the outcome.",
                  paths, project=project)
        return
    try:
        events.log(message)
        events.state("failed")
    except OSError as e:
        log_error(COMPONENT, f"job {job_id} was failed worker_lost, but writing to its "
                  f"events {path} failed ({e}); the job record holds the outcome.",
                  paths, project=project)
    finally:
        events.close()


def _advice(paths: BoxPaths, action: str, project: str | None) -> str:
    try:
        return recovery_advice(paths, action.split(".", 1)[-1], project)
    except StateError as e:
        return f"no way out is known for this action ({e}); check what it changed"


def _audit(paths: BoxPaths, record: dict[str, Any], error: dict[str, str]) -> None:
    """The outcome audit line the worker could not write. params are left
    out: the runner loads no registry to redact them, and the job's
    accepted line already carries them."""
    line = audit_record(record["principal"], record["action"], "failed",
                        code=error["code"], message=error["message"], job=record["id"])
    try:
        AuditLog(paths.audit_log, create=False).append(line)
    except AuditError as e:
        log_error("audit", f"could not record the outcome of {record['action']} (job "
                  f"{record['id']}): {e}", paths, detail={"outcome": "failed"})
        notify(paths, "boxmunge: audit log write failed",
               f"The outcome (failed, worker_lost) of {record['action']} by "
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
