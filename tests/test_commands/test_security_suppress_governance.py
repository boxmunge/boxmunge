# SPDX-License-Identifier: Apache-2.0
"""Suppression governance (audit B-15): bounded expiry, operator-only host scope."""
from __future__ import annotations

import os
import time
from datetime import date, datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from boxmunge.commands import security_suppress_targets
from boxmunge.commands.security_suppress import cmd_security_suppress
from boxmunge.cve.suppressions import MAX_SUPPRESSION_DAYS
from boxmunge.shell import operator_only_reason, run_command
from tests.test_commands.cve_helpers import make_box


# 23:30 UTC on 1 July is already 00:30 on 2 July in any zone ahead of UTC:
# the hour in which a local-date reading of "today" disagrees with the
# command's UTC date.
_NOW = datetime(2026, 7, 1, 23, 30, tzinfo=timezone.utc)
_UTC_TODAY = _NOW.date()


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return _NOW.astimezone(tz) if tz else _NOW.astimezone().replace(tzinfo=None)


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch):
    monkeypatch.setattr(security_suppress_targets, "datetime", _FrozenDatetime)


@pytest.fixture
def utc_plus_one():
    """Local time one hour ahead of UTC (BST-like), restored afterwards."""
    saved = os.environ.get("TZ")
    os.environ["TZ"] = "XST-1"
    time.tzset()
    try:
        yield
    finally:
        if saved is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = saved
        time.tzset()


def _args(days: int, *scope: str, today: date = _UTC_TODAY) -> list[str]:
    until = (today + timedelta(days=days)).isoformat()
    return ["CVE-2026-1234", *scope, "--until", until, "--reason", "reviewed"]


def test_max_duration_is_ninety_days() -> None:
    assert MAX_SUPPRESSION_DAYS == 90


def test_suppress_accepts_the_maximum(tmp_path) -> None:
    paths = make_box(tmp_path)
    assert cmd_security_suppress(_args(90, "--project", "demo"), paths) == 0


def test_the_maximum_counts_from_the_utc_date_not_the_local_one(
    tmp_path, capsys, utc_plus_one,
) -> None:
    local_today = _FrozenDatetime.now().date()
    assert local_today == _UTC_TODAY + timedelta(days=1)  # the boundary hour
    paths = make_box(tmp_path)
    assert cmd_security_suppress(_args(90, "--project", "demo", today=local_today), paths) == 1
    assert f"latest {(_UTC_TODAY + timedelta(days=90)).isoformat()}" in capsys.readouterr().err
    assert cmd_security_suppress(_args(90, "--project", "demo"), paths) == 0


@pytest.mark.parametrize("scope", [("--project", "demo"), ("--host",)])
def test_suppress_refuses_beyond_the_maximum(tmp_path, capsys, scope) -> None:
    paths = make_box(tmp_path)
    assert cmd_security_suppress(_args(91, *scope), paths) == 1
    assert "at most 90 days ahead" in capsys.readouterr().err


def test_suppress_refuses_the_far_future(tmp_path) -> None:
    paths = make_box(tmp_path)
    args = ["CVE-2026-1234", "--project", "demo", "--until", "9999-12-31",
            "--reason", "forever"]
    assert cmd_security_suppress(args, paths) == 1
    assert not (paths.project_dir("demo") / "security" / "suppressions.yml").exists()


@pytest.mark.parametrize("args", [
    ["suppress", "CVE-2026-1234", "--host", "--until", "2026-12-01", "--reason", "x"],
    ["suppress", "--current", "--host", "--until", "2026-12-01", "--reason", "x"],
    ["unsuppress", "CVE-2026-1234", "--host"],
])
def test_deploy_shell_refuses_host_scope(args, capsys) -> None:
    with patch("boxmunge.shell.subprocess.run") as run:
        assert run_command("security", args) == 1
        run.assert_not_called()
    assert "operator-only" in capsys.readouterr().err


@pytest.mark.parametrize("args", [
    [],
    ["demo"],
    ["scan"],
    ["suppress", "CVE-2026-1234", "--project", "demo", "--until", "2026-12-01",
     "--reason", "x"],
    ["unsuppress", "CVE-2026-1234", "--project", "demo"],
    ["resume", "demo"],
])
def test_deploy_shell_allows_project_scope(args) -> None:
    assert operator_only_reason("security", args) is None
    with patch("boxmunge.shell.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0)
        assert run_command("security", args) == 0
        run.assert_called_once_with(["boxmunge-server", "security", *args])
