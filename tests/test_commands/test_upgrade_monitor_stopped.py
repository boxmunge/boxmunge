# SPDX-License-Identifier: Apache-2.0
"""A platform upgrade does not restart a project the health monitor stopped.

The monitor stops a project after a critical result, and the stop stands
until `recover` or a deploy starts it again. Restarting it from an upgrade
would run the project with the stop marker still standing (nothing bumps
last_started_at), so the upgrade leaves it stopped and names it.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.commands.health_state import MONITOR_STOPPED, is_monitor_stopped
from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.commands.upgrade_steps import Restart, restart_projects
from boxmunge.state import write_state
from tests.test_commands.test_upgrade_dry_run_and_pause import _project, _setup


def _monitor_stop(paths, name: str, at: datetime) -> None:
    write_state(paths.project_health_state(name), {
        "status": MONITOR_STOPPED, "failure_reason": "db unreachable",
        "stopped_at": at.isoformat(),
    })


@pytest.fixture
def paths(tmp_path: Path):
    paths = _setup(tmp_path)
    _project(paths, "live")
    _project(paths, "stopped")
    _monitor_stop(paths, "stopped", datetime.now(timezone.utc))
    return paths


def test_restart_leaves_monitor_stopped_project_stopped(paths) -> None:
    with patch("boxmunge.compose_guard.compose_up") as up:
        restart = restart_projects(paths, refused=())
    assert [c.kwargs["project_name"] for c in up.call_args_list] == ["live"]
    assert restart == Restart(succeeded=["live"], monitor_stopped=["stopped"])
    assert is_monitor_stopped("stopped", paths)


def test_restart_starts_a_project_whose_stop_was_superseded(paths) -> None:
    """A later deploy, resume or recover start ends the stop."""
    stopped_at = datetime.now(timezone.utc) - timedelta(hours=1)
    _monitor_stop(paths, "stopped", stopped_at)
    write_state(paths.project_deploy_state("stopped"), {
        "last_started_at": (stopped_at + timedelta(minutes=5)).isoformat(),
    })
    with patch("boxmunge.compose_guard.compose_up") as up:
        restart = restart_projects(paths, refused=())
    assert sorted(c.kwargs["project_name"] for c in up.call_args_list) == ["live", "stopped"]
    assert restart.monitor_stopped == []


@patch("boxmunge.commands.upgrade_cmd.caddy_reload")
@patch("boxmunge.compose_guard.compose_up")
def test_apply_names_monitor_stopped_projects(up, _reload, paths, capsys) -> None:
    assert run_upgrade(paths, apply_only=True) == 0
    assert [c.kwargs["project_name"] for c in up.call_args_list] == ["live"]
    out = capsys.readouterr().out
    assert "stopped by the health monitor" in out and "stopped" in out.split("monitor")[-1]
    entries = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
    done = [e for e in entries if e["msg"].startswith("Apply ")]
    assert done[-1]["detail"]["monitor_stopped"] == ["stopped"]
