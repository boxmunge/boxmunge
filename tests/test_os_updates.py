"""Evidence that OS updates are arriving (boxmunge.os_updates).

The systemctl output below is what Debian 13 (apt 3.0.3, unattended-upgrades
2.12) prints; see the module docstring for what was verified there.
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.os_updates import STAMP_MAX_AGE, inspect_os_updates

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)

OK_SHOW = ("Result=success\nExecMainExitTimestamp=Fri 2026-10-16 03:33:47 UTC\n"
           "ExecMainStatus=0\nLoadState=loaded\n")
FAILED_SHOW = ("Result=exit-code\nExecMainExitTimestamp=Fri 2026-10-16 03:35:05 UTC\n"
               "ExecMainStatus=100\nLoadState=loaded\n")
MISSING_SHOW = "Result=success\nExecMainExitTimestamp=\nExecMainStatus=0\nLoadState=not-found\n"


class FakeSystemctl:
    def __init__(self, *, active: str = "active", show: dict[str, str] | None = None,
                 raises: Exception | None = None) -> None:
        self.active = active
        self.show = show or {}
        self.raises = raises
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess:
        self.calls.append(args)
        if self.raises:
            raise self.raises
        if args[0] == "is-active":
            rc = 0 if self.active == "active" else 3
            return subprocess.CompletedProcess(args, rc, stdout=f"{self.active}\n", stderr="")
        assert args[0] == "show"
        return subprocess.CompletedProcess(
            args, 0, stdout=self.show.get(args[-1], OK_SHOW), stderr="")


def _stamp(tmp_path, *, hours_ago: float):
    stamp = tmp_path / "update-stamp"
    stamp.touch()
    t = (NOW - timedelta(hours=hours_ago)).timestamp()
    os.utime(stamp, (t, t))
    return stamp


def test_fresh_stamp_and_successful_units_are_healthy(tmp_path):
    status = inspect_os_updates(now=NOW, stamp=_stamp(tmp_path, hours_ago=20),
                                run=FakeSystemctl())
    assert status.problems == ()
    assert "package lists refreshed 20h ago" in status.summary()


def test_stale_stamp_is_a_problem_even_though_the_unit_succeeded(tmp_path):
    """The production failure: apt-get update exited 100 for months while
    apt-daily.service kept ending in Result=success."""
    status = inspect_os_updates(now=NOW, stamp=_stamp(tmp_path, hours_ago=24 * 100 + 3),
                                run=FakeSystemctl())
    assert [p.key for p in status.problems] == ["stamp:stale"]
    summary = status.summary()
    assert "last refreshed successfully 100d 3h ago" in summary
    assert "`apt-get update` shows the failing source" in summary


def test_stamp_just_inside_the_limit_is_fine(tmp_path):
    hours = STAMP_MAX_AGE.total_seconds() / 3600 - 0.1
    status = inspect_os_updates(now=NOW, stamp=_stamp(tmp_path, hours_ago=hours),
                                run=FakeSystemctl())
    assert status.problems == ()


def test_missing_stamp_means_never_refreshed(tmp_path):
    status = inspect_os_updates(now=NOW, stamp=tmp_path / "update-stamp",
                                run=FakeSystemctl())
    assert [p.key for p in status.problems] == ["stamp:missing"]
    assert "never been refreshed successfully" in status.summary()


def test_failed_unit_names_the_unit_and_status(tmp_path):
    run = FakeSystemctl(show={"apt-daily-upgrade.service": FAILED_SHOW})
    status = inspect_os_updates(now=NOW, stamp=_stamp(tmp_path, hours_ago=1), run=run)
    assert [p.key for p in status.problems] == ["unit:apt-daily-upgrade.service:exit-code"]
    text = status.summary()
    assert "last apt-daily-upgrade.service run failed (result exit-code, exit status 100" in text
    assert "journalctl -u apt-daily-upgrade.service" in text


def test_missing_unit_is_a_problem(tmp_path):
    run = FakeSystemctl(show={"apt-daily.service": MISSING_SHOW})
    status = inspect_os_updates(now=NOW, stamp=_stamp(tmp_path, hours_ago=1), run=run)
    assert [p.key for p in status.problems] == ["unit:apt-daily.service:missing"]


def test_inactive_unattended_upgrades_is_still_checked(tmp_path):
    run = FakeSystemctl(active="inactive")
    status = inspect_os_updates(now=NOW, stamp=_stamp(tmp_path, hours_ago=1), run=run)
    assert [p.key for p in status.problems] == ["unattended:inactive"]
    assert "unattended-upgrades is not active (inactive)" in status.summary()


@pytest.mark.parametrize("exc", [FileNotFoundError("systemctl"),
                                 subprocess.TimeoutExpired("systemctl", 10)])
def test_systemctl_failure_is_reported_not_skipped(tmp_path, exc):
    run = FakeSystemctl(raises=exc)
    status = inspect_os_updates(now=NOW, stamp=_stamp(tmp_path, hours_ago=1), run=run)
    assert {p.key for p in status.problems} == {
        "unattended:unknown", "unit:apt-daily.service:unknown",
        "unit:apt-daily-upgrade.service:unknown"}


def test_problem_keys_are_stable_as_the_stamp_ages(tmp_path):
    """Alert dedupe keys on these; the text changes every run."""
    a = inspect_os_updates(now=NOW, stamp=_stamp(tmp_path, hours_ago=50), run=FakeSystemctl())
    b = inspect_os_updates(now=NOW, stamp=_stamp(tmp_path, hours_ago=80), run=FakeSystemctl())
    assert [p.key for p in a.problems] == [p.key for p in b.problems]
    assert a.summary() != b.summary()
