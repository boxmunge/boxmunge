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


def _touch(path, *, hours_ago: float):
    path.touch()
    t = (NOW - timedelta(hours=hours_ago)).timestamp()
    os.utime(path, (t, t))
    return path


def _inspect(tmp_path, *, update: float | None = 20, upgrade: float | None = 18,
             conf: float | None = 24 * 200, run=None):
    """Probe a fake host. A None age means that file does not exist."""
    files = {}
    for name, age in (("update-stamp", update), ("upgrade-stamp", upgrade),
                      ("20auto-upgrades", conf)):
        path = tmp_path / name
        files[name] = _touch(path, hours_ago=age) if age is not None else path
    return inspect_os_updates(now=NOW, stamp=files["update-stamp"],
                              upgrade_stamp=files["upgrade-stamp"],
                              auto_conf=files["20auto-upgrades"],
                              run=run or FakeSystemctl())


def _keys(status):
    return [p.key for p in status.problems]


def test_fresh_stamps_and_successful_units_are_healthy(tmp_path):
    status = _inspect(tmp_path)
    assert status.problems == ()
    assert "package lists refreshed 20h ago" in status.summary()
    assert "updates installed 18h ago" in status.summary()


def test_stale_update_stamp_is_a_problem_even_though_the_unit_succeeded(tmp_path):
    """A dead apt source: apt-get update exited 100 for months while
    apt-daily.service kept ending in Result=success."""
    status = _inspect(tmp_path, update=24 * 100 + 3)
    assert _keys(status) == ["stamp:stale"]
    summary = status.summary()
    assert "package lists refreshed 100d 3h ago" in summary
    assert "not being fetched" in summary
    assert "`apt-get update` shows the failing source" in summary


def test_stale_upgrade_stamp_is_a_problem_even_though_the_unit_succeeded(tmp_path):
    """The production failure: unattended-upgrade crashed on every run on a
    malformed origins list while apt-daily-upgrade.service ended in success."""
    status = _inspect(tmp_path, upgrade=24 * 199)
    assert _keys(status) == ["upgrade-stamp:stale"]
    summary = status.summary()
    assert "unattended-upgrade succeeded 199d 0h ago" in summary
    assert "not being installed" in summary
    assert "unattended-upgrades.log" in summary


def test_stamp_just_inside_the_limit_is_fine(tmp_path):
    hours = STAMP_MAX_AGE.total_seconds() / 3600 - 0.1
    assert _inspect(tmp_path, update=hours, upgrade=hours).problems == ()


def test_missing_stamps_on_an_old_install_mean_never_succeeded(tmp_path):
    status = _inspect(tmp_path, update=None, upgrade=None)
    assert _keys(status) == ["stamp:missing", "upgrade-stamp:missing"]
    assert "upgrade-stamp is missing), so OS security updates are not being installed" \
        in status.summary()


def test_missing_stamps_on_a_new_install_are_expected(tmp_path):
    """A box set up today has not had its first apt-daily runs yet."""
    status = _inspect(tmp_path, update=None, upgrade=None, conf=5)
    assert status.problems == ()
    assert "updates installed not yet (first run pending)" in status.summary()


def test_a_new_install_still_reports_a_stale_stamp(tmp_path):
    """The grace covers a stamp that does not exist yet, nothing else."""
    status = _inspect(tmp_path, update=24 * 3, conf=5)
    assert _keys(status) == ["stamp:stale"]


def test_missing_auto_upgrades_config_is_a_problem(tmp_path):
    status = _inspect(tmp_path, conf=None)
    assert _keys(status) == ["auto-upgrades:unconfigured"]
    assert "automatic updates are not configured" in status.summary()


def test_failed_unit_names_the_unit_and_status(tmp_path):
    status = _inspect(tmp_path, run=FakeSystemctl(show={"apt-daily-upgrade.service": FAILED_SHOW}))
    assert _keys(status) == ["unit:apt-daily-upgrade.service:exit-code"]
    text = status.summary()
    assert "last apt-daily-upgrade.service run failed (result exit-code, exit status 100" in text
    assert "journalctl -u apt-daily-upgrade.service" in text


def test_missing_unit_is_a_problem(tmp_path):
    status = _inspect(tmp_path, run=FakeSystemctl(show={"apt-daily.service": MISSING_SHOW}))
    assert _keys(status) == ["unit:apt-daily.service:missing"]


def test_inactive_unattended_upgrades_is_still_checked(tmp_path):
    status = _inspect(tmp_path, run=FakeSystemctl(active="inactive"))
    assert _keys(status) == ["unattended:inactive"]
    assert "unattended-upgrades is not active (inactive)" in status.summary()


@pytest.mark.parametrize("exc", [FileNotFoundError("systemctl"),
                                 subprocess.TimeoutExpired("systemctl", 10)])
def test_systemctl_failure_is_reported_not_skipped(tmp_path, exc):
    status = _inspect(tmp_path, run=FakeSystemctl(raises=exc))
    assert set(_keys(status)) == {
        "unattended:unknown", "unit:apt-daily.service:unknown",
        "unit:apt-daily-upgrade.service:unknown"}


def test_problem_keys_are_stable_as_the_stamps_age(tmp_path):
    """Alert dedupe keys on these; the text changes every run."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a = _inspect(tmp_path / "a", update=50, upgrade=60)
    b = _inspect(tmp_path / "b", update=80, upgrade=90)
    assert _keys(a) == _keys(b) == ["stamp:stale", "upgrade-stamp:stale"]
    assert a.summary() != b.summary()
