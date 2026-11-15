# SPDX-License-Identifier: Apache-2.0
"""Health check: the job runner's path unit is active, and nothing waits in
the queue for long. An inactive path unit is an error on purpose: install
enables it, and without it no queued job ever starts."""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone

from boxmunge.api.timefmt import format_utc
from boxmunge.health_checks import jobs_runner
from boxmunge.health_checks.jobs_runner import JOB_QUEUE_STALE, check_jobs_runner

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
FIX = ("sudo systemctl reset-failed boxmunge-jobs.path boxmunge-jobs.service && "
       "sudo systemctl start boxmunge-jobs.path")


def _show(path_state: str = "active", path_result: str = "success",
          service_state: str = "inactive"):
    def show():
        return jobs_runner.parse_show(
            f"Id=boxmunge-jobs.path\nActiveState={path_state}\nResult={path_result}\n\n"
            f"Id=boxmunge-jobs.service\nActiveState={service_state}\nResult=success\n")
    return show


def _queue(paths, n: int, created: datetime, state: str = "queued") -> str:
    job_id = "01J" + "Q" * 22 + str(n)
    paths.jobs_queue.mkdir(parents=True, exist_ok=True)
    (paths.jobs_queue / f"{job_id}.json").write_text(json.dumps({
        "id": job_id, "action": "project.deploy", "principal": "plugin:webui",
        "project": "shop", "state": state, "created_at": format_utc(created),
        "started_at": None, "finished_at": None, "error": None, "result": None,
        "params": '{"project":"shop"}', "worker": None}))
    return job_id


def test_idle_runner_is_ok(paths) -> None:
    check = check_jobs_runner(paths, show=_show(), now=NOW)
    assert (check.name, check.status, check.detail) == ("jobs-runner", "ok", "queue empty")


def test_unfinished_jobs_are_counted(paths) -> None:
    _queue(paths, 1, NOW - timedelta(minutes=1))
    _queue(paths, 2, NOW)
    check = check_jobs_runner(paths, show=_show(service_state="active"), now=NOW)
    assert (check.status, check.detail) == ("ok", "2 unfinished")


def test_rate_limited_path_unit_is_an_error_naming_the_fix(paths) -> None:
    check = check_jobs_runner(paths, show=_show("failed", "unit-start-limit-hit"), now=NOW)
    assert check.status == "error"
    assert "unit-start-limit-hit" in check.detail and "rate-limited" in check.detail
    assert FIX in check.detail and "journalctl -u boxmunge-jobs.service" in check.detail


def test_an_inactive_path_unit_is_an_error(paths) -> None:
    check = check_jobs_runner(paths, show=_show("inactive"), now=NOW)
    assert check.status == "error"
    assert "boxmunge-jobs.path is inactive" in check.detail and FIX in check.detail
    assert "rate-limited" not in check.detail


def test_stale_queued_job_warns(paths) -> None:
    job_id = _queue(paths, 1, NOW - JOB_QUEUE_STALE - timedelta(minutes=2))
    _queue(paths, 2, NOW - timedelta(minutes=1))
    check = check_jobs_runner(paths, show=_show(), now=NOW)
    assert check.status == "warn"
    assert job_id in check.detail and "12 min" in check.detail
    assert "journalctl -u boxmunge-jobs.service" in check.detail


def test_a_queued_job_just_inside_the_limit_is_ok(paths) -> None:
    _queue(paths, 1, NOW - JOB_QUEUE_STALE + timedelta(seconds=1))
    assert check_jobs_runner(paths, show=_show(), now=NOW).status == "ok"


def test_an_unreadable_queue_record_warns_naming_it(paths) -> None:
    paths.jobs_queue.mkdir(parents=True)
    bad = "01J" + "Q" * 23
    (paths.jobs_queue / f"{bad}.json").write_text("{")
    check = check_jobs_runner(paths, show=_show(), now=NOW)
    assert check.status == "warn" and bad in check.detail and "not JSON" in check.detail


def test_systemctl_timing_out_warns_naming_the_command(paths, monkeypatch) -> None:
    def timeout(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs["timeout"])
    monkeypatch.setattr(subprocess, "run", timeout)
    check = check_jobs_runner(paths, now=NOW)
    assert check.status == "warn" and "systemctl show boxmunge-jobs.path" in check.detail


def test_the_check_reads_both_units_from_one_show(monkeypatch) -> None:
    seen = []

    def run(cmd, **kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=(
            "Id=boxmunge-jobs.path\nActiveState=active\nResult=success\n\n"
            "Id=boxmunge-jobs.service\nActiveState=inactive\nResult=success\n"), stderr="")
    monkeypatch.setattr(subprocess, "run", run)
    states = jobs_runner.unit_states()
    assert seen == [["systemctl", "show", "boxmunge-jobs.path", "boxmunge-jobs.service",
                     "-p", "Id", "-p", "ActiveState", "-p", "Result"]]
    assert states["boxmunge-jobs.path"] == {"ActiveState": "active", "Result": "success"}
