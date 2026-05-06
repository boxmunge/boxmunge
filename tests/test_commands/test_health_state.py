"""Tests for boxmunge health-state machine and alerting.

Extracted from test_check.py: these tests exercise update_health_state and
the deploy/resume grace window in commands/health_state.py.
"""

from unittest.mock import patch

from boxmunge.paths import BoxPaths


class TestDeployResumeGracePeriod:
    """Health-timer fires in the second between deploy/resume and the
    container becoming responsive. The first warning-level failure
    in that window is a false alarm — the next check (15 min later)
    is the real verdict. Mask the alert without hiding genuine outages
    that persist past the grace window.
    """

    def _setup(self, paths: BoxPaths):
        paths.state.mkdir(parents=True, exist_ok=True)
        (paths.state / "deploy").mkdir(parents=True, exist_ok=True)
        (paths.state / "health").mkdir(parents=True, exist_ok=True)
        (paths.root / "logs").mkdir(parents=True, exist_ok=True)
        (paths.root / "config").mkdir(parents=True, exist_ok=True)
        paths.config_file.write_text("hostname: t\nadmin_email: t@t\n")

    def test_warning_within_grace_does_not_mark_failing(self, paths: BoxPaths):
        from datetime import datetime, timezone
        from boxmunge.commands.health_state import update_health_state
        from boxmunge.state import read_state, write_state

        self._setup(paths)
        # Project just started: last_started_at = now
        now_iso = datetime.now(timezone.utc).isoformat()
        write_state(paths.project_deploy_state("myapp"), {
            "current_ref": "main",
            "deployed_at": now_iso,
            "last_started_at": now_iso,
        })

        # Warning-level failure (smoke flake while service is starting)
        update_health_state("myapp", check_result=1, message="connection refused", paths=paths)

        state = read_state(paths.project_health_state("myapp"))
        assert state.get("status") != "failing", (
            f"warning within grace must not mark failing; got status={state.get('status')!r}"
        )
        assert state.get("consecutive_failures", 0) == 0, (
            "consecutive_failures must not increment during grace window"
        )

    def test_warning_outside_grace_marks_failing(self, paths: BoxPaths):
        from datetime import datetime, timedelta, timezone
        from boxmunge.commands.health_state import update_health_state
        from boxmunge.state import read_state, write_state

        self._setup(paths)
        # Started 10 minutes ago — well outside grace
        old_iso = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        write_state(paths.project_deploy_state("myapp"), {
            "current_ref": "main",
            "deployed_at": old_iso,
            "last_started_at": old_iso,
        })

        update_health_state("myapp", check_result=1, message="real failure", paths=paths)

        state = read_state(paths.project_health_state("myapp"))
        assert state["status"] == "failing", (
            f"warning outside grace must mark failing; got {state.get('status')!r}"
        )

    def test_critical_within_grace_still_stops_containers(self, paths: BoxPaths):
        """Critical failures (smoke exit 2) are too serious to mask. They
        stop containers and mark status critical_stopped regardless of
        deploy timing — operators MUST be alerted."""
        from datetime import datetime, timezone
        from boxmunge.commands.health_state import update_health_state
        from boxmunge.state import read_state, write_state

        self._setup(paths)
        now_iso = datetime.now(timezone.utc).isoformat()
        write_state(paths.project_deploy_state("myapp"), {
            "current_ref": "main",
            "deployed_at": now_iso,
            "last_started_at": now_iso,
        })

        # Stub compose_down so we don't actually shell out
        with patch("boxmunge.commands.health_state.compose_down"):
            update_health_state("myapp", check_result=2, message="hard failure", paths=paths)

        state = read_state(paths.project_health_state("myapp"))
        assert state["status"] == "critical_stopped", (
            "critical failures during grace must still escalate"
        )

    def test_no_started_state_falls_through_to_normal_failure_path(self, paths: BoxPaths):
        """Old projects that haven't been started since the upgrade have
        no last_started_at field; behavior must match pre-grace logic
        (warning increments consecutive_failures)."""
        from boxmunge.commands.health_state import update_health_state
        from boxmunge.state import read_state

        self._setup(paths)
        # No deploy state at all (or no last_started_at field)
        update_health_state("myapp", check_result=1, message="some warning", paths=paths)

        state = read_state(paths.project_health_state("myapp"))
        assert state["status"] == "failing"
        assert state["consecutive_failures"] == 1


class TestCriticalCleanup:
    """Cleanup paths around the critical failure handler.

    7b: when compose_down fails during a critical health event we MUST log
    the failure — silently swallowing it leaves operators with no signal
    that containers may still be running.

    7e: when Pushover is not configured but a critical event fires we MUST
    log "alert dropped" — the previous code happily called send_notification
    with empty strings and the alert silently went nowhere.
    """

    def _setup(self, paths: BoxPaths):
        paths.state.mkdir(parents=True, exist_ok=True)
        (paths.state / "deploy").mkdir(parents=True, exist_ok=True)
        (paths.state / "health").mkdir(parents=True, exist_ok=True)
        (paths.root / "logs").mkdir(parents=True, exist_ok=True)
        (paths.root / "config").mkdir(parents=True, exist_ok=True)

    def _write_pushover_config(self, paths: BoxPaths) -> None:
        paths.config_file.write_text(
            "hostname: t\nadmin_email: t@t\n"
            "pushover:\n  user_key: u\n  app_token: a\n"
        )

    def test_compose_down_failure_is_logged(self, paths: BoxPaths):
        from boxmunge.commands.health_state import update_health_state
        from boxmunge.docker import DockerError

        self._setup(paths)
        self._write_pushover_config(paths)

        with patch("boxmunge.commands.health_state.compose_down",
                   side_effect=DockerError("daemon gone")), \
             patch("boxmunge.commands.health_state.send_notification"), \
             patch("boxmunge.commands.health_state.log_error") as mock_err:
            update_health_state(
                "myapp", check_result=2, message="hard failure", paths=paths,
            )

        # Multiple log_error calls happen (CRITICAL + compose_down failure).
        # We assert one of them references the compose_down failure.
        compose_failure_calls = [
            c for c in mock_err.call_args_list
            if "compose down failed during critical" in c.args[1]
        ]
        assert len(compose_failure_calls) == 1, (
            f"expected compose_down failure to be logged; got {mock_err.call_args_list}"
        )

    def test_critical_without_pushover_logs_alert_dropped(self, paths: BoxPaths):
        from boxmunge.commands.health_state import update_health_state

        self._setup(paths)
        # No pushover config: write a minimal config that omits keys.
        paths.config_file.write_text("hostname: t\nadmin_email: t@t\n")

        with patch("boxmunge.commands.health_state.send_notification") as mock_send, \
             patch("boxmunge.commands.health_state.compose_down"), \
             patch("boxmunge.commands.health_state.log_error") as mock_err:
            update_health_state(
                "myapp", check_result=2, message="hard failure", paths=paths,
            )

        # send_notification must NOT be called with empty creds.
        mock_send.assert_not_called()
        dropped_calls = [
            c for c in mock_err.call_args_list
            if "Pushover not configured" in c.args[1] and "alert dropped" in c.args[1]
        ]
        assert len(dropped_calls) == 1, (
            f"expected alert-dropped log; got {mock_err.call_args_list}"
        )
