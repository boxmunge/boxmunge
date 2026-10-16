"""A health-monitor critical stop is sticky until recover or a restart (audit C-04).

Regression for the auditor's probe: after tick 1 stopped the project, tick 2
ran smoke against the removed containers, got "No such container", rewrote
the state to ``failing`` with an "infrastructure" alert, and ``recover``
then refused because the project was no longer ``critical_stopped``.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.paths import BoxPaths
from boxmunge.state import read_state, write_state
from tests.deploy_helpers import mark_deployed

NAME = "myapp"
NO_CONTAINER = f"Error response from daemon: No such container: {NAME}-web-1"


@pytest.fixture
def paths(tmp_path: Path, fake_containers) -> BoxPaths:
    fake_containers.run(NAME, "web", "sha256:" + "1" * 64)  # smoke finds it by label
    p = BoxPaths(root=tmp_path / "bm")
    for d in ["config", f"projects/{NAME}", "state/deploy", "state/health",
              "caddy/sites", "logs"]:
        (p.root / d).mkdir(parents=True, exist_ok=True)
    p.config_file.write_text(
        "hostname: t\nadmin_email: a@b\n"
        "pushover:\n  user_key: u\n  app_token: a\n"
    )
    (p.project_dir(NAME) / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": NAME,
        "source": "bundle", "hosts": [f"{NAME}.test"],
        "services": {"web": {"port": 8080, "smoke": "smoke.sh",
                             "routes": [{"path": "/"}]}},
    }))
    (p.project_dir(NAME) / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    mark_deployed(p, NAME)
    write_state(p.project_deploy_state(NAME), {
        "current_ref": "r1",
        "last_started_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
    })
    return p


class _Smoke:
    """Stands in for ``docker exec ... smoke.sh``: returns queued results."""

    def __init__(self, *results: tuple[int, str]):
        self.results = list(results)
        self.calls = 0

    def __call__(self, cmd, **_kw):
        assert cmd[:2] == ["docker", "exec"], cmd
        self.calls += 1
        rc, stderr = self.results.pop(0) if len(self.results) > 1 else self.results[0]
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr=stderr)


def _tick(paths: BoxPaths, smoke: _Smoke, down, push) -> int:
    from boxmunge.commands.check import run_check_all
    with patch("boxmunge.commands.check.subprocess.run", smoke), \
         patch("boxmunge.commands.health_state.compose_down", down), \
         patch("boxmunge.notify.send_notification", push):
        return run_check_all(paths, read_only=False)


class TestStickyCriticalStop:
    def test_later_ticks_leave_state_alone_and_recover_still_works(self, paths):
        from unittest.mock import MagicMock
        down, push = MagicMock(), MagicMock(return_value=True)

        rc1 = _tick(paths, _Smoke((2, "db unreachable")), down, push)
        assert rc1 == 2
        state1 = read_state(paths.project_health_state(NAME))
        assert state1["status"] == "critical_stopped"
        assert state1["failure_reason"] == "db unreachable"
        assert state1["stopped_at"]
        assert down.call_count == 1 and push.call_count == 1

        smoke = _Smoke((1, NO_CONTAINER))
        for _ in range(4):
            assert _tick(paths, smoke, down, push) == 2
        assert smoke.calls == 0, "no smoke against containers the monitor removed"
        state = read_state(paths.project_health_state(NAME))
        assert state["status"] == "critical_stopped"
        assert state["failure_reason"] == "db unreachable"
        assert state["stopped_at"] == state1["stopped_at"]
        assert down.call_count == 1, "no second compose_down"
        assert push.call_count == 1, "no 'infrastructure' re-alert"

        from boxmunge.commands import recover_cmd
        with patch("boxmunge.compose_guard.compose_up"), \
             patch.object(recover_cmd, "caddy_reload"), \
             patch.object(recover_cmd, "prepare_caddy_config"), \
             patch.object(recover_cmd, "prepare_compose_override"), \
             patch.object(recover_cmd, "run_smoke", return_value=(True, "")):
            assert recover_cmd.run_recover(NAME, paths, yes=True) == 0
        assert read_state(paths.project_health_state(NAME))["status"] == "ok"

    def test_successful_deploy_after_stop_clears_it(self, paths):
        from unittest.mock import MagicMock
        down, push = MagicMock(), MagicMock(return_value=True)
        _tick(paths, _Smoke((2, "db unreachable")), down, push)
        # A successful deploy records a last_started_at after the stop, and
        # its grace window has passed by the next tick.
        deploy = read_state(paths.project_deploy_state(NAME))
        stopped_at = read_state(paths.project_health_state(NAME))["stopped_at"]
        deploy["last_started_at"] = (
            datetime.fromisoformat(stopped_at) + timedelta(seconds=1)
        ).isoformat()
        write_state(paths.project_deploy_state(NAME), deploy)

        smoke = _Smoke((0, ""))
        assert _tick(paths, smoke, down, push) == 0
        assert smoke.calls == 1
        assert read_state(paths.project_health_state(NAME))["status"] == "ok"
        titles = [c.args[2] for c in push.call_args_list]
        assert any("RECOVERED" in t for t in titles)

    def test_update_health_state_never_overwrites_a_standing_stop(self, paths):
        """Defence in depth for callers that do not skip a stopped project."""
        from unittest.mock import MagicMock
        from boxmunge.commands.health_state import update_health_state
        down, push = MagicMock(), MagicMock(return_value=True)
        with patch("boxmunge.commands.health_state.compose_down", down), \
             patch("boxmunge.notify.send_notification", push):
            update_health_state(NAME, 2, "db unreachable", paths)
            for result, msg in [(1, "smoke could not run"), (0, ""), (2, "other")]:
                update_health_state(NAME, result, msg, paths)
        state = read_state(paths.project_health_state(NAME))
        assert state["status"] == "critical_stopped"
        assert state["failure_reason"] == "db unreachable"
        assert down.call_count == 1 and push.call_count == 1

    def test_read_only_check_all_reports_stop_without_writing(self, paths):
        from unittest.mock import MagicMock
        from boxmunge.commands.check import run_check_all
        _tick(paths, _Smoke((2, "db unreachable")), MagicMock(), MagicMock(return_value=True))
        before = paths.project_health_state(NAME).read_text()
        smoke = _Smoke((1, NO_CONTAINER))
        with patch("boxmunge.commands.check.subprocess.run", smoke):
            assert run_check_all(paths, read_only=True) == 2
        assert smoke.calls == 0
        assert paths.project_health_state(NAME).read_text() == before


class TestHealthReport:
    def test_lifecycle_lists_monitor_stopped_as_warning(self, paths):
        from boxmunge.commands.health_cmd import check_lifecycle_blocked
        write_state(paths.project_health_state(NAME), {
            "status": "critical_stopped", "failure_reason": "db unreachable",
            "stopped_at": datetime.now(timezone.utc).isoformat(),
        })
        check = check_lifecycle_blocked(paths)
        assert check.status == "warn", "never 'error': probation rolls back on exit 2"
        assert "monitor-stopped" in check.detail and NAME in check.detail
        assert "recover" in check.detail
