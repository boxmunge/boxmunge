# SPDX-License-Identifier: Apache-2.0
"""Pruning finished jobs: the newest 200 stay, and so does anything from the last 14 days."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.api.job_retention import JOB_RETAIN_AGE, JOB_RETAIN_COUNT, TMP_SWEEP_AGE, prune
from boxmunge.api.timefmt import format_utc
from boxmunge.paths import BoxPaths

NOW = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
OLD = NOW - JOB_RETAIN_AGE - timedelta(days=1)


@pytest.fixture
def paths(tmp_path: Path) -> BoxPaths:
    p = BoxPaths(root=tmp_path / "box")
    p.jobs_queue.mkdir(parents=True)
    return p


def _id(n: int) -> str:
    return f"01J{n:023d}"


def _job(paths: BoxPaths, n: int, finished: datetime) -> str:
    job_id = _id(n)
    record = {"id": job_id, "state": "succeeded", "finished_at": format_utc(finished)}
    (paths.jobs_dir / f"{job_id}.json").write_text(json.dumps(record))
    (paths.jobs_dir / f"{job_id}.events.jsonl").write_text("")
    (paths.jobs_dir / f"{job_id}.lock").write_text("")
    return job_id


def _present(paths: BoxPaths, job_id: str) -> bool:
    return (paths.jobs_dir / f"{job_id}.json").exists()


def _age(path: Path, by: timedelta) -> None:
    stamp = (NOW - by).timestamp()
    os.utime(path, (stamp, stamp))


def test_keeps_newest_200_even_when_older_than_14_days(paths: BoxPaths) -> None:
    ids = [_job(paths, n, OLD - timedelta(minutes=n)) for n in range(JOB_RETAIN_COUNT)]
    assert prune(paths, NOW) == []
    assert all(_present(paths, i) for i in ids)


def test_keeps_everything_from_the_last_14_days_even_past_200(paths: BoxPaths) -> None:
    ids = [_job(paths, n, NOW - timedelta(days=13, minutes=n)) for n in range(JOB_RETAIN_COUNT + 20)]
    assert prune(paths, NOW) == []
    assert all(_present(paths, i) for i in ids)


def test_deletes_only_beyond_both(paths: BoxPaths) -> None:
    recent = [_job(paths, n, NOW - timedelta(minutes=n)) for n in range(JOB_RETAIN_COUNT)]
    old_extra = _job(paths, 900, OLD)
    fresh_extra = _job(paths, 901, NOW - timedelta(days=1))
    # fresh_extra ranks past 200 but finished inside 14 days, so it stays.
    assert prune(paths, NOW) == [old_extra]
    assert not (paths.jobs_dir / f"{old_extra}.json").exists()
    assert not (paths.jobs_dir / f"{old_extra}.events.jsonl").exists()
    assert not (paths.jobs_dir / f"{old_extra}.lock").exists()
    assert all(_present(paths, i) for i in recent + [fresh_extra])


def test_never_touches_queue(paths: BoxPaths) -> None:
    queued = paths.jobs_queue / f"{_id(1)}.json"
    queued.write_text(json.dumps({"id": _id(1), "state": "queued", "finished_at": None}))
    stale = paths.jobs_queue / ".x.tmp"
    stale.write_text("")
    _age(queued, timedelta(days=60))
    _age(stale, timedelta(days=60))
    for n in range(JOB_RETAIN_COUNT + 5):
        _job(paths, n, OLD - timedelta(minutes=n))
    prune(paths, NOW)
    assert queued.exists() and stale.exists()


def test_sweeps_stale_temps_and_orphans(paths: BoxPaths) -> None:
    stale_tmp = paths.jobs_dir / ".abc.json.tmp"
    fresh_tmp = paths.jobs_dir / ".def.json.tmp"
    old_events = paths.jobs_dir / f"{_id(5)}.events.jsonl"
    old_lock = paths.jobs_dir / f"{_id(5)}.lock"
    fresh_orphan = paths.jobs_dir / f"{_id(6)}.events.jsonl"
    running_events = paths.jobs_dir / f"{_id(7)}.events.jsonl"
    for f in (stale_tmp, fresh_tmp, old_events, old_lock, fresh_orphan, running_events):
        f.write_text("")
    (paths.jobs_queue / f"{_id(7)}.json").write_text("{}")
    _age(stale_tmp, TMP_SWEEP_AGE + timedelta(minutes=1))
    _age(fresh_tmp, TMP_SWEEP_AGE - timedelta(minutes=1))
    for f in (old_events, old_lock, running_events):
        _age(f, JOB_RETAIN_AGE + timedelta(days=1))
    _age(fresh_orphan, timedelta(days=1))
    assert prune(paths, NOW) == []
    assert not stale_tmp.exists() and not old_events.exists() and not old_lock.exists()
    assert fresh_tmp.exists() and fresh_orphan.exists() and running_events.exists()


@pytest.mark.parametrize("content", ["{not json", '{"id": "x", "finished_at": null}', "[]"])
def test_unreadable_record_is_kept_and_logged(paths: BoxPaths, content: str) -> None:
    bad = paths.jobs_dir / f"{_id(3)}.json"
    bad.write_text(content)
    for n in range(JOB_RETAIN_COUNT + 1):
        _job(paths, n + 10, OLD - timedelta(minutes=n))
    with patch("boxmunge.api.job_retention.log_error") as log:
        prune(paths, NOW)
    assert bad.exists()
    assert any(str(bad) in call.args[1] for call in log.call_args_list)
