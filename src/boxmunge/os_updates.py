# SPDX-License-Identifier: Apache-2.0
"""Evidence that the OS is actually fetching and installing its updates.

"unattended-upgrades is enabled" says nothing about whether updates arrive:
one dead third-party apt source makes every ``apt-get update`` exit 100,
and unattended-upgrades then keeps "upgrading" against package lists that
never change. So this module looks for evidence instead (verified on
Debian 13 with apt 3.0 and unattended-upgrades 2.12):

- ``/var/lib/apt/periodic/update-stamp`` is touched by apt.systemd.daily
  (run by apt-daily.service) only after ``apt-get update`` succeeded. Its
  age is the evidence that package lists are being refreshed. Debian has no
  ``update-success-stamp``; that file comes from Ubuntu's
  update-notifier-common.
- apt.systemd.daily swallows a failed ``apt-get update``, so apt-daily.service
  still ends in ``Result=success``. The units' last results are checked as
  well, because they catch the script or the unit failing outright.
- unattended-upgrades must still be active.

Everything here is readable without root: the stamp directory is 0755 and
``systemctl show`` needs no privilege. Nothing here runs ``apt-get update``.
Every probe failure is reported as a problem, never skipped.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

UPDATE_STAMP = Path("/var/lib/apt/periodic/update-stamp")
# apt-daily.timer fires twice a day with up to 12h of random delay, and
# apt.systemd.daily refreshes at most once per calendar day, so a healthy
# stamp is under ~36h old. 48h means at least one day's refresh has failed.
STAMP_MAX_AGE = timedelta(hours=48)
APT_UNITS = ("apt-daily.service", "apt-daily-upgrade.service")
UNATTENDED_UNIT = "unattended-upgrades"
_SYSTEMCTL_TIMEOUT = 10

Runner = Callable[[list[str]], subprocess.CompletedProcess]


@dataclass(frozen=True)
class Problem:
    """One reason OS updates may not be arriving.

    ``key`` is stable while the same thing stays wrong (alert dedupe keys on
    it); ``text`` says what is wrong now; ``hint`` says how to see the cause.
    """
    key: str
    text: str
    hint: str


@dataclass(frozen=True)
class OsUpdateStatus:
    problems: tuple[Problem, ...] = field(default_factory=tuple)
    stamp_age: timedelta | None = None

    def summary(self) -> str:
        """One line: the problems with their hints, or the evidence of health."""
        if self.problems:
            return "; ".join(f"{p.text} — {p.hint}" for p in self.problems)
        assert self.stamp_age is not None
        return (f"unattended-upgrades active; package lists refreshed "
                f"{format_age(self.stamp_age)} ago; last apt-daily runs succeeded")


def format_age(age: timedelta) -> str:
    hours = int(age.total_seconds() // 3600)
    return f"{hours // 24}d {hours % 24}h" if hours >= 24 else f"{hours}h"


def _systemctl(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl", *args], capture_output=True, text=True, check=False,
        timeout=_SYSTEMCTL_TIMEOUT,
    )


def _run(run: Runner, args: list[str]) -> subprocess.CompletedProcess | str:
    """Run systemctl; a string is the reason it could not be run."""
    try:
        return run(args)
    except FileNotFoundError:
        return "systemctl not found"
    except subprocess.TimeoutExpired:
        return f"systemctl timed out after {_SYSTEMCTL_TIMEOUT}s"


def _unattended_problem(run: Runner) -> Problem | None:
    result = _run(run, ["is-active", UNATTENDED_UNIT])
    if isinstance(result, str):
        return Problem("unattended:unknown", f"cannot tell whether {UNATTENDED_UNIT} is active: "
                       f"{result}", "run `systemctl status unattended-upgrades`")
    if result.returncode != 0:
        state = result.stdout.strip() or f"exit {result.returncode}"
        return Problem("unattended:inactive", f"{UNATTENDED_UNIT} is not active ({state})",
                       "as root, run `systemctl enable --now unattended-upgrades`")
    return None


def _stamp_problem(stamp: Path, now: datetime) -> tuple[Problem | None, timedelta | None]:
    hint = "as root, `apt-get update` shows the failing source"
    try:
        mtime = stamp.stat().st_mtime
    except FileNotFoundError:
        return Problem("stamp:missing", f"package lists have never been refreshed "
                       f"successfully ({stamp} is missing)", hint), None
    except OSError as e:
        return Problem("stamp:unreadable", f"cannot read {stamp}: {e}", hint), None
    age = now - datetime.fromtimestamp(mtime, timezone.utc)
    if age > STAMP_MAX_AGE:
        return Problem("stamp:stale", f"package lists last refreshed successfully "
                       f"{format_age(age)} ago, so OS security updates are not being "
                       f"fetched", hint), age
    return None, age


def _parse_show(stdout: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            props[key] = value
    return props


def _unit_problem(run: Runner, unit: str) -> Problem | None:
    hint = f"`journalctl -u {unit}` shows why"
    result = _run(run, ["show", "-p", "LoadState,Result,ExecMainStatus,ExecMainExitTimestamp",
                        unit])
    if isinstance(result, str):
        return Problem(f"unit:{unit}:unknown", f"cannot read the last {unit} run: {result}",
                       hint)
    props = _parse_show(result.stdout)
    if result.returncode != 0 or "Result" not in props:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        return Problem(f"unit:{unit}:unknown", f"cannot read the last {unit} run: {detail}",
                       hint)
    if props.get("LoadState") == "not-found":
        return Problem(f"unit:{unit}:missing", f"{unit} is not installed",
                       "as root, run `apt-get install --reinstall apt`")
    if props["Result"] != "success":
        when = props.get("ExecMainExitTimestamp") or "unknown time"
        return Problem(f"unit:{unit}:{props['Result']}",
                       f"last {unit} run failed (result {props['Result']}, exit status "
                       f"{props.get('ExecMainStatus', '?')}, at {when})", hint)
    return None


def inspect_os_updates(*, now: datetime | None = None, stamp: Path = UPDATE_STAMP,
                       run: Runner = _systemctl) -> OsUpdateStatus:
    """Gather the evidence. Never raises for a probe failure: it is a problem."""
    now = now or datetime.now(timezone.utc)
    problems: list[Problem] = []
    unattended = _unattended_problem(run)
    if unattended:
        problems.append(unattended)
    stamp_issue, age = _stamp_problem(stamp, now)
    if stamp_issue:
        problems.append(stamp_issue)
    for unit in APT_UNITS:
        issue = _unit_problem(run, unit)
        if issue:
            problems.append(issue)
    return OsUpdateStatus(problems=tuple(problems), stamp_age=age)
