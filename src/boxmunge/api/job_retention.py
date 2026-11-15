# SPDX-License-Identifier: Apache-2.0
"""Pruning finished jobs.

A finished job is deleted only when it is outside the newest JOB_RETAIN_COUNT
and finished more than JOB_RETAIN_AGE ago: whichever rule keeps more wins.
Only state/jobs/ is touched, never queue/. A job's files go record first,
then events, then lock, so an interrupted prune leaves orphans (swept later)
and never a record without its events.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.log import log_error
from boxmunge.paths import BoxPaths

JOB_RETAIN_COUNT = 200
JOB_RETAIN_AGE = timedelta(days=14)
TMP_SWEEP_AGE = timedelta(hours=1)

_COMPONENT = "job-retention"
_JOB_ID = "[0-9A-HJKMNP-TV-Z]{26}"
_RECORD_RE = re.compile(rf"({_JOB_ID})\.json")
_SIDE_FILE_RE = re.compile(rf"({_JOB_ID})\.(?:events\.jsonl|lock)")


def prune(paths: BoxPaths, now: datetime) -> list[str]:
    """Delete finished jobs beyond both retention rules, and sweep stale
    temp files and orphaned events/lock files. Returns the ids deleted."""
    jobs = paths.jobs_dir
    if not jobs.is_dir():
        return []
    finished: list[tuple[str, str, datetime]] = []  # (id, finished_at text, finished_at)
    for entry in sorted(jobs.iterdir()):
        match = _RECORD_RE.fullmatch(entry.name)
        if match is None:
            continue
        try:
            finished.append(_finished_at(entry, match.group(1)))
        except ValueError as e:
            log_error(_COMPONENT, f"Kept unreadable job record {entry}: {e}", paths)
    finished.sort(key=lambda f: (f[2], f[0]), reverse=True)
    deleted = []
    for job_id, _, when in finished[JOB_RETAIN_COUNT:]:
        if now - when > JOB_RETAIN_AGE:
            _delete_job(jobs, job_id)
            deleted.append(job_id)
    _sweep(jobs, paths.jobs_queue, now)
    return deleted


def _finished_at(path: Path, job_id: str) -> tuple[str, str, datetime]:
    """(id, finished_at text, finished_at) of a record, ValueError if unusable.
    Reads only what retention needs; the record's other fields are the
    store's business."""
    try:
        text = read_text_nofollow_or_none(path)
        if text is None:
            raise ValueError("vanished while reading")
        record = json.loads(text)
        if not isinstance(record, dict) or record.get("id") != job_id:
            raise ValueError("not a record for this job id")
        stamp = record.get("finished_at")
        if not isinstance(stamp, str):
            raise ValueError("finished_at is not a timestamp")
        when = datetime.fromisoformat(stamp[:-1] + "+00:00" if stamp.endswith("Z") else stamp)
    except (OSError, UnicodeDecodeError) as e:
        raise ValueError(f"cannot read: {e}") from e
    if when.tzinfo is None:
        raise ValueError("finished_at has no timezone")
    return job_id, stamp, when.astimezone(timezone.utc)


def _delete_job(jobs: Path, job_id: str) -> None:
    for name in (f"{job_id}.json", f"{job_id}.events.jsonl", f"{job_id}.lock"):
        try:
            os.unlink(jobs / name)
        except FileNotFoundError:
            pass


def _sweep(jobs: Path, queue: Path, now: datetime) -> None:
    """Remove temp files older than TMP_SWEEP_AGE, and events/lock files
    with no record (finished or queued) older than JOB_RETAIN_AGE."""
    for entry in sorted(jobs.iterdir()):
        name = entry.name
        if name.startswith(".") and name.endswith(".tmp"):
            limit = TMP_SWEEP_AGE
        else:
            match = _SIDE_FILE_RE.fullmatch(name)
            if match is None:
                continue
            job_id = match.group(1)
            if os.path.lexists(jobs / f"{job_id}.json") or os.path.lexists(queue / f"{job_id}.json"):
                continue
            limit = JOB_RETAIN_AGE
        try:
            modified = datetime.fromtimestamp(entry.lstat().st_mtime, tz=timezone.utc)
            if now - modified > limit:
                os.unlink(entry)
        except FileNotFoundError:
            pass
