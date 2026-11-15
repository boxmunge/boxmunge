# SPDX-License-Identifier: Apache-2.0
"""Health check: is the job runner's path unit active, and is the queue
moving?

boxmunge-jobs.path starts boxmunge-jobs.service (the runner) whenever
state/jobs/queue/ holds a record, and at boot. A path unit that is not
active is an error, on purpose: install enables it, and without it no
queued job ever starts, so probation rolling an upgrade back over it is
right. It fails when its service was rate-limited (StartLimitBurst starts
within StartLimitIntervalSec), which the detail says, with the commands
that start it again.

A job queued for longer than JOB_QUEUE_STALE that has not started, or a
record in queue/ that cannot be read, warns.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Callable

from boxmunge.api.actions import build_registry
from boxmunge.api.jobs import JobStore
from boxmunge.commands.health_cmd import HealthCheck

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "jobs-runner"
JOB_QUEUE_STALE = timedelta(minutes=10)
PATH_UNIT = "boxmunge-jobs.path"
SERVICE = "boxmunge-jobs.service"
SHOW = ["systemctl", "show", PATH_UNIT, SERVICE, "-p", "Id", "-p", "ActiveState", "-p", "Result"]
SHOW_TIMEOUT = 10
FIX = (f"as supervisor: sudo systemctl reset-failed {PATH_UNIT} {SERVICE} && "
       f"sudo systemctl start {PATH_UNIT}, then see why the runner failed: "
       f"journalctl -u {SERVICE}")
RATE_LIMITED = "unit-start-limit-hit"

UnitStates = dict[str, dict[str, str]]


class ShowFailed(Exception):
    """systemctl show gave no answer to read the units' states from."""


def parse_show(text: str) -> UnitStates:
    """`systemctl show <units> -p Id ...` output: one block of Key=value
    lines per unit, blocks apart by a blank line, keyed by Id."""
    states: UnitStates = {}
    for block in text.strip().split("\n\n"):
        fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        unit = fields.pop("Id", None)
        if unit is None:
            raise ShowFailed(f"`{' '.join(SHOW)}` printed a block with no Id: {block[:200]!r}")
        states[unit] = fields
    return states


def unit_states() -> UnitStates:
    """The path unit's and the service's ActiveState and Result."""
    try:
        done = subprocess.run(SHOW, capture_output=True, text=True, timeout=SHOW_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise ShowFailed(f"`{' '.join(SHOW)}` did not answer within {SHOW_TIMEOUT}s") from e
    if done.returncode != 0:
        raise ShowFailed(f"`{' '.join(SHOW)}` exited {done.returncode}: "
                         f"{done.stderr.strip()[:300]}")
    return parse_show(done.stdout)


def check_jobs_runner(paths: BoxPaths, *, show: Callable[[], UnitStates] = unit_states,
                      now: datetime | None = None) -> HealthCheck:
    try:
        states = show()
    except ShowFailed as e:
        return HealthCheck(NAME, "warn", f"cannot tell whether {PATH_UNIT} is active: {e}")
    path = states.get(PATH_UNIT)
    if path is None or "ActiveState" not in path:
        return HealthCheck(NAME, "warn", f"cannot tell whether {PATH_UNIT} is active: "
                           f"`{' '.join(SHOW)}` did not report it")
    if path["ActiveState"] != "active":
        result = path.get("Result", "unknown")
        why = (f"rate-limited: {SERVICE} failed to start too often, so systemd stopped "
               f"starting it" if result == RATE_LIMITED else "not started")
        return HealthCheck(NAME, "error", (
            f"{PATH_UNIT} is {path['ActiveState']} (result {result}), {why}; no queued job "
            f"runs until it is active again. Start it {FIX}"))
    return _queue_health(paths, now or datetime.now(timezone.utc))


def _queue_health(paths: BoxPaths, now: datetime) -> HealthCheck:
    results = {action.name: action.result for action in build_registry().actions()}
    listing = JobStore(paths, result_schemas=results.get).unfinished()
    problems = [f"queue record {u['id']} cannot be read: {u['problem']}"
                for u in listing.unreadable]
    for job in listing.jobs:
        waited = now - _parse(job["created_at"])
        if job["state"] == "queued" and waited > JOB_QUEUE_STALE:
            what = " ".join(filter(None, (job["action"], job["project"])))
            problems.append(f"job {job['id']} ({what}) has been queued for "
                            f"{int(waited.total_seconds() // 60)} min without starting; "
                            f"see why the runner does not start it: journalctl -u {SERVICE}")
    if problems:
        return HealthCheck(NAME, "warn", "; ".join(problems))
    count = len(listing.jobs)
    return HealthCheck(NAME, "ok", f"{count} unfinished" if count else "queue empty")


def _parse(stamp: str) -> datetime:
    """A record's timestamp (JOB_SCHEMA's TIMESTAMP: UTC, trailing Z)."""
    return datetime.fromisoformat(stamp.removesuffix("Z") + "+00:00")
