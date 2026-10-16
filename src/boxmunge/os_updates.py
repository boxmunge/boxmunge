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
- ``/var/lib/apt/periodic/upgrade-stamp`` is touched only after
  unattended-upgrade itself exited 0. Its age is the evidence that updates
  are being installed: the unit still ends in ``Result=success`` when
  unattended-upgrade crashes (as it did on every run on hosts whose
  bootstrap wrote a malformed origins list).
- A missing stamp is expected only on a host configured for automatic
  updates less than ``STAMP_MAX_AGE`` ago (the age of ``20auto-upgrades``).
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
UPGRADE_STAMP = Path("/var/lib/apt/periodic/upgrade-stamp")
AUTO_UPGRADES_CONF = Path("/etc/apt/apt.conf.d/20auto-upgrades")
# apt-daily.timer fires twice a day with up to 12h of random delay, and
# apt.systemd.daily refreshes at most once per calendar day, so a healthy
# stamp is under ~36h old. 48h means at least one day's refresh has failed.
# apt-daily-upgrade.timer fires daily, so the same limit holds for upgrades.
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
    upgrade_age: timedelta | None = None

    def summary(self) -> str:
        """One line: the problems with their hints, or the evidence of health."""
        if self.problems:
            return "; ".join(f"{p.text} — {p.hint}" for p in self.problems)
        return (f"unattended-upgrades active; package lists refreshed "
                f"{_ago(self.stamp_age)}; updates installed {_ago(self.upgrade_age)}; "
                f"last apt-daily runs succeeded")


def _ago(age: timedelta | None) -> str:
    return "not yet (first run pending)" if age is None else f"{format_age(age)} ago"


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


@dataclass(frozen=True)
class _Stamp:
    key: str        # problem-key prefix
    done: str       # what a fresh stamp proves happened
    failing: str    # what a stale stamp means
    hint: str


_UPDATE = _Stamp("stamp", "package lists refreshed",
                 "OS security updates are not being fetched",
                 "as root, `apt-get update` shows the failing source")
_UPGRADE = _Stamp("upgrade-stamp", "unattended-upgrade succeeded",
                  "OS security updates are not being installed",
                  "/var/log/unattended-upgrades/unattended-upgrades.log shows why")


def _age(path: Path, now: datetime) -> timedelta:
    return now - datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)


def _configured_recently(conf: Path, now: datetime) -> bool | Problem:
    """Whether automatic updates were set up too recently to have run yet."""
    try:
        return _age(conf, now) <= STAMP_MAX_AGE
    except FileNotFoundError:
        return Problem("auto-upgrades:unconfigured", f"automatic updates are not "
                       f"configured ({conf} is missing)",
                       "re-run the boxmunge installer's unattended-upgrades step")
    except OSError as e:
        return Problem("auto-upgrades:unreadable", f"cannot read {conf}: {e}",
                       f"as root, check {conf}")


def _stamp_problem(kind: _Stamp, stamp: Path, now: datetime,
                   recent: bool | Problem) -> tuple[Problem | None, timedelta | None]:
    try:
        age = _age(stamp, now)
    except FileNotFoundError:
        if recent is True:
            return None, None
        return Problem(f"{kind.key}:missing", f"never recorded that {kind.done} "
                       f"({stamp} is missing), so {kind.failing}", kind.hint), None
    except OSError as e:
        return Problem(f"{kind.key}:unreadable", f"cannot read {stamp}: {e}",
                       kind.hint), None
    if age > STAMP_MAX_AGE:
        return Problem(f"{kind.key}:stale", f"last recorded that {kind.done} "
                       f"{format_age(age)} ago, so {kind.failing}", kind.hint), age
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
                       upgrade_stamp: Path = UPGRADE_STAMP,
                       auto_conf: Path = AUTO_UPGRADES_CONF,
                       run: Runner = _systemctl) -> OsUpdateStatus:
    """Gather the evidence. Never raises for a probe failure: it is a problem."""
    now = now or datetime.now(timezone.utc)
    problems: list[Problem] = []
    unattended = _unattended_problem(run)
    if unattended:
        problems.append(unattended)
    recent = _configured_recently(auto_conf, now)
    if isinstance(recent, Problem):
        problems.append(recent)
    stamp_issue, age = _stamp_problem(_UPDATE, stamp, now, recent)
    if stamp_issue:
        problems.append(stamp_issue)
    upgrade_issue, upgrade_age = _stamp_problem(_UPGRADE, upgrade_stamp, now, recent)
    if upgrade_issue:
        problems.append(upgrade_issue)
    for unit in APT_UNITS:
        issue = _unit_problem(run, unit)
        if issue:
            problems.append(issue)
    return OsUpdateStatus(problems=tuple(problems), stamp_age=age, upgrade_age=upgrade_age)
