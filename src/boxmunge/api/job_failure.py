# SPDX-License-Identifier: Apache-2.0
"""Failing a job its own worker never concluded, and expiring stale queued jobs.

The job runner fails jobs whose worker was lost or died before its claim;
the runner and the worker both expire a queued job that waited longer than
JOB_MAX_QUEUED_AGE. Either way the job gets the events, outcome audit line
and alert its worker would have written (record_failure).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from boxmunge.api.audit import AuditError, AuditLog, audit_record
from boxmunge.api.job_events import EventLog
from boxmunge.api.job_recovery import retry_command
from boxmunge.api.job_writer import fail_unclaimed
from boxmunge.log import log_error
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

COMPONENT = "jobs"
# A queued job older than this is failed, never run: what it was asked to do
# may no longer be wanted (it waited out a platform rollback, or a job runner
# that was down).
JOB_MAX_QUEUED_AGE = timedelta(hours=2)
EXPIRED = "expired"


def is_expired(record: dict[str, Any], now: datetime) -> bool:
    """Whether *record* is queued and was created over JOB_MAX_QUEUED_AGE ago."""
    if record["state"] != "queued":
        return False
    created = datetime.fromisoformat(record["created_at"])
    return now - created > JOB_MAX_QUEUED_AGE


def expired_message(record: dict[str, Any]) -> str:
    hours = int(JOB_MAX_QUEUED_AGE.total_seconds() // 3600)
    return (f"This job was queued at {record['created_at']} and had not started {hours} "
            f"hours later, so it was failed without being run: a job queued that long (for "
            f"example across a platform rollback, or while the job runner was down) may no "
            f"longer be wanted. If it still is, run the same call again: "
            f"{retry_command(record)}")


def fail_if_expired(paths: BoxPaths, record: dict[str, Any]) -> bool:
    """Fail queued *record* with the error `expired` if it is older than
    JOB_MAX_QUEUED_AGE; nothing of it runs. True if it was too old to run
    (even when a worker claimed it first, which then has it)."""
    now = clock()
    if not is_expired(record, now):
        return False
    error = {"code": EXPIRED, "message": expired_message(record)}
    if fail_unclaimed(paths, record["id"], error=error, now=now) is not None:
        record_failure(paths, record, error, f"boxmunge: job {record['id']} "
                       f"({record['action']} {record['project']}) expired in the queue")
    return True


def record_failure(paths: BoxPaths, record: dict[str, Any], error: dict[str, str],
                   title: str) -> None:
    """The events, outcome audit line and alert of a job failed for its worker."""
    _write_failure_events(paths, record, error["message"])
    audit_outcome(paths, record, "failed", error)
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


def audit_outcome(paths: BoxPaths, record: dict[str, Any], outcome: str,
                  error: dict[str, str] | None) -> None:
    """The outcome audit line the worker could not write. params are left
    out: no registry is loaded to redact them, and the job's accepted line
    already carries them."""
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


def clock() -> datetime:
    """The time fail_if_expired goes by."""
    return datetime.now(timezone.utc)
