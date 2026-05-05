"""Tests for boxmunge check command — health checking logic."""

import json
import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

from boxmunge.commands.check import (
    parse_smoke_stderr,
    interpret_smoke_result,
    run_check,
    run_smoke_in_container,
    SmokeResult,
)
from boxmunge.paths import BoxPaths


class TestParseSmokeStderr:
    def test_single_line(self) -> None:
        msg = parse_smoke_stderr("Backend unhealthy\n")
        assert msg == "Backend unhealthy"

    def test_multiple_lines_collapsed(self) -> None:
        msg = parse_smoke_stderr("line1\nline2\nline3\n")
        assert "Manual failure analysis required" in msg

    def test_empty_stderr(self) -> None:
        msg = parse_smoke_stderr("")
        assert "no detail provided" in msg.lower()

    def test_blank_lines_ignored(self) -> None:
        msg = parse_smoke_stderr("\n  \nActual message\n  \n")
        assert msg == "Actual message"


class TestInterpretSmokeResult:
    def test_exit_zero_is_healthy(self) -> None:
        result = interpret_smoke_result(0, "")
        assert result.status == "ok"

    def test_exit_one_is_warning(self) -> None:
        result = interpret_smoke_result(1, "Low disk space\n")
        assert result.status == "warning"
        assert result.message == "Low disk space"

    def test_exit_two_is_critical(self) -> None:
        result = interpret_smoke_result(2, "Security breach detected\n")
        assert result.status == "critical"
        assert result.message == "Security breach detected"

    def test_other_exit_code_is_warning(self) -> None:
        result = interpret_smoke_result(127, "command not found\n")
        assert result.status == "warning"


class TestRunSmokeInContainer:
    MANIFEST = {
        "project": "myapp",
        "hosts": ["app.example.com"],
        "services": {"web": {
            "port": 8080, "health": "/healthz",
            "routes": [{"path": "/"}],
            "smoke": "boxmunge-scripts/smoke.sh",
        }},
    }

    def test_no_smoke_returns_ok(self, tmp_path: Path) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        result = run_smoke_in_container(tmp_path, manifest, ["compose.yml"])
        assert result.status == "ok"

    @patch("boxmunge.commands.check.subprocess.run")
    def test_successful_smoke(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        result = run_smoke_in_container(
            tmp_path, self.MANIFEST, ["compose.yml", "compose.boxmunge.yml"],
        )
        assert result.status == "ok"
        # Uses docker exec directly (not docker compose exec)
        call_args = mock_run.call_args[0][0]
        assert call_args[0:2] == ["docker", "exec"]
        assert "myapp-web-1" in call_args
        assert "/boxmunge-scripts/smoke.sh" in call_args
        # Service name passed as $1
        assert call_args[-1] == "web"

    @patch("boxmunge.commands.check.subprocess.run")
    def test_failed_smoke(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=1, stderr="Connection refused\n")
        result = run_smoke_in_container(
            tmp_path, self.MANIFEST, ["compose.yml", "compose.boxmunge.yml"],
        )
        assert result.status == "warning"
        assert "Connection refused" in result.message

    @patch("boxmunge.commands.check.subprocess.run")
    def test_staging_container_name(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        run_smoke_in_container(
            tmp_path, self.MANIFEST,
            ["compose.yml", "compose.boxmunge-staging.yml"],
            project_name="myapp-staging",
        )
        call_args = mock_run.call_args[0][0]
        assert "myapp-staging-web-1" in call_args

    @patch("boxmunge.commands.check.subprocess.run")
    def test_timeout_returns_warning(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=60)
        result = run_smoke_in_container(
            tmp_path, self.MANIFEST, ["compose.yml"],
        )
        assert result.status == "warning"
        assert "timed out" in result.message

    @patch("boxmunge.commands.check.subprocess.run")
    def test_multiple_services(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Each service with smoke gets its own docker exec."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        manifest = {
            "project": "myapp",
            "services": {
                "web": {
                    "port": 8080, "routes": [{"path": "/"}],
                    "smoke": "boxmunge-scripts/smoke-web.sh",
                },
                "api": {
                    "port": 9000, "routes": [{"path": "/api/*"}],
                    "smoke": "boxmunge-scripts/smoke-api.sh",
                },
            },
        }
        result = run_smoke_in_container(tmp_path, manifest, ["compose.yml"])
        assert result.status == "ok"
        assert mock_run.call_count == 2
        containers = [c[0][0][2] for c in mock_run.call_args_list]
        assert "myapp-web-1" in containers
        assert "myapp-api-1" in containers

    @patch("boxmunge.commands.check.subprocess.run")
    def test_stops_on_first_failure(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """If the first service fails, don't run the rest."""
        mock_run.return_value = MagicMock(returncode=1, stderr="Backend down\n")
        manifest = {
            "project": "myapp",
            "services": {
                "web": {
                    "port": 8080, "routes": [{"path": "/"}],
                    "smoke": "boxmunge-scripts/smoke-web.sh",
                },
                "api": {
                    "port": 9000, "routes": [{"path": "/api/*"}],
                    "smoke": "boxmunge-scripts/smoke-api.sh",
                },
            },
        }
        result = run_smoke_in_container(tmp_path, manifest, ["compose.yml"])
        assert result.status == "warning"
        assert mock_run.call_count == 1


class TestRunCheckPreRegistered:
    def test_pre_registered_returns_error(self, paths: BoxPaths, capsys) -> None:
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "secrets.env").write_text("KEY=val\n")

        result = run_check("myapp", paths)
        assert result == 1
        captured = capsys.readouterr()
        assert "pre-registered" in captured.err
        assert "boxmunge deploy myapp" in captured.err


class TestRunCheckSurfacesProfileOff:
    """Task 19: profile: off must surface in `boxmunge check` output.

    The line is informational/posture — it does not escalate the exit code
    (the operator already opted out with a reason; alerting via Pushover
    every 15 minutes would be noise, not signal).
    """

    def _write_manifest(self, paths: BoxPaths, name: str, manifest: dict) -> None:
        import yaml
        paths.project_dir(name).mkdir(parents=True, exist_ok=True)
        paths.project_manifest(name).write_text(yaml.dump(manifest))
        # Mark as deployed so run_check doesn't reject as pre-registered
        paths.project_deploy_state(name).parent.mkdir(parents=True, exist_ok=True)
        paths.project_deploy_state(name).write_text('{"current_ref": "main"}')

    def test_off_project_emits_security_off_warning(
        self, paths: BoxPaths, capsys,
    ) -> None:
        self._write_manifest(paths, "myapp", {
            "schema_version": 1, "id": "01TEST", "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "security": {"profile": "off", "reason": "legacy binary"},
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        })

        run_check("myapp", paths)
        out = capsys.readouterr().out
        assert "SECURITY OFF" in out
        assert "web" in out
        assert "legacy binary" in out

    def test_default_profile_no_security_message(
        self, paths: BoxPaths, capsys,
    ) -> None:
        self._write_manifest(paths, "myapp", {
            "schema_version": 1, "id": "01TEST", "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        })

        run_check("myapp", paths)
        out = capsys.readouterr().out
        assert "SECURITY" not in out
        assert "security:" not in out

    def test_off_does_not_escalate_exit_code(
        self, paths: BoxPaths,
    ) -> None:
        """profile: off is a posture finding the operator opted into. It
        does not flip a healthy project to warning/critical for the runtime
        health pipeline (which would trigger Pushover every 15 minutes)."""
        self._write_manifest(paths, "myapp", {
            "schema_version": 1, "id": "01TEST", "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "security": {"profile": "off", "reason": "legacy"},
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        })

        # No smoke test, no other failures -> exit 0 even with profile: off
        result = run_check("myapp", paths)
        assert result == 0


class TestDeployResumeGracePeriod:
    """Health-timer fires in the second between deploy/resume and the
    container becoming responsive. The first warning-level failure
    in that window is a false alarm — the next check (15 min later)
    is the real verdict. Mask the alert without hiding genuine outages
    that persist past the grace window.
    """

    def _setup(self, paths: BoxPaths):
        from boxmunge.state import write_state
        paths.state.mkdir(parents=True, exist_ok=True)
        (paths.state / "deploy").mkdir(parents=True, exist_ok=True)
        (paths.state / "health").mkdir(parents=True, exist_ok=True)
        (paths.root / "logs").mkdir(parents=True, exist_ok=True)
        (paths.root / "config").mkdir(parents=True, exist_ok=True)
        paths.config_file.write_text("hostname: t\nadmin_email: t@t\n")

    def test_warning_within_grace_does_not_mark_failing(self, paths: BoxPaths):
        from datetime import datetime, timezone
        from boxmunge.commands.check import update_health_state
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
        from boxmunge.commands.check import update_health_state
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
        from unittest.mock import patch
        from boxmunge.commands.check import update_health_state
        from boxmunge.state import read_state, write_state

        self._setup(paths)
        now_iso = datetime.now(timezone.utc).isoformat()
        write_state(paths.project_deploy_state("myapp"), {
            "current_ref": "main",
            "deployed_at": now_iso,
            "last_started_at": now_iso,
        })

        # Stub compose_down so we don't actually shell out
        with patch("boxmunge.commands.check.compose_down"):
            update_health_state("myapp", check_result=2, message="hard failure", paths=paths)

        state = read_state(paths.project_health_state("myapp"))
        assert state["status"] == "critical_stopped", (
            "critical failures during grace must still escalate"
        )

    def test_no_started_state_falls_through_to_normal_failure_path(self, paths: BoxPaths):
        """Old projects that haven't been started since the upgrade have
        no last_started_at field; behavior must match pre-grace logic
        (warning increments consecutive_failures)."""
        from boxmunge.commands.check import update_health_state
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
        from boxmunge.state import write_state
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
        from boxmunge.commands.check import update_health_state
        from boxmunge.docker import DockerError

        self._setup(paths)
        self._write_pushover_config(paths)

        with patch("boxmunge.commands.check.compose_down",
                   side_effect=DockerError("daemon gone")), \
             patch("boxmunge.commands.check.send_notification"), \
             patch("boxmunge.commands.check.log_error") as mock_err:
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
        from boxmunge.commands.check import update_health_state

        self._setup(paths)
        # No pushover config: write a minimal config that omits keys.
        paths.config_file.write_text("hostname: t\nadmin_email: t@t\n")

        with patch("boxmunge.commands.check.send_notification") as mock_send, \
             patch("boxmunge.commands.check.compose_down"), \
             patch("boxmunge.commands.check.log_error") as mock_err:
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


class TestCheckAllReadOnly:
    """Audit Finding 1: cmd_check_all is documented near 'read-only'
    introspection but writes health state, calls compose_down, and
    sends Pushover. Provide a --read-only flag that runs the same
    per-project checks without those side effects."""

    def _write_project(self, paths: BoxPaths, name: str, manifest: dict) -> None:
        import yaml
        paths.project_dir(name).mkdir(parents=True, exist_ok=True)
        paths.project_manifest(name).write_text(yaml.dump(manifest))
        paths.project_deploy_state(name).parent.mkdir(parents=True, exist_ok=True)
        paths.project_deploy_state(name).write_text('{"current_ref": "main"}')

    def _minimal_manifest(self) -> dict:
        return {
            "schema_version": 2, "id": "01TEST",
            "project": "myapp", "source": "bundle",
            "hosts": ["myapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }

    def test_default_invocation_mutates_state(
        self, paths: BoxPaths, monkeypatch,
    ) -> None:
        from unittest.mock import patch
        from boxmunge.commands.check import run_check_all

        self._write_project(paths, "myapp", self._minimal_manifest())

        with patch("boxmunge.commands.check.update_health_state") as mock_update:
            run_check_all([], paths)

        assert mock_update.called, (
            "default cmd_check_all invocation must continue calling "
            "update_health_state — that's the timer-driven mutator path"
        )

    def test_read_only_skips_state_mutation(
        self, paths: BoxPaths,
    ) -> None:
        from unittest.mock import patch
        from boxmunge.commands.check import run_check_all

        self._write_project(paths, "myapp", self._minimal_manifest())

        with patch("boxmunge.commands.check.update_health_state") as mock_update:
            run_check_all(["--read-only"], paths)

        assert not mock_update.called, (
            "--read-only must not call update_health_state — no health "
            "state writes, no compose_down, no Pushover"
        )

    def test_read_only_returns_worst_status(
        self, paths: BoxPaths, monkeypatch,
    ) -> None:
        """Even with --read-only, the exit code reflects the worst severity
        per the existing convention so callers (operators, CI) can branch
        on success/failure."""
        from boxmunge.commands import check as check_mod
        from boxmunge.commands.check import run_check_all

        # Two projects, one healthy (returns 0) and one critical (returns 2).
        m1 = self._minimal_manifest()
        m1["project"] = "okapp"
        self._write_project(paths, "okapp", m1)
        m2 = self._minimal_manifest()
        m2["project"] = "badapp"
        self._write_project(paths, "badapp", m2)

        # Stub run_check so we don't depend on real smoke execution.
        def _fake_run_check(name: str, paths: BoxPaths, verbose: bool = True) -> int:
            return 2 if name == "badapp" else 0

        monkeypatch.setattr(check_mod, "run_check", _fake_run_check)

        result = run_check_all(["--read-only"], paths)
        assert result == 2


class TestCheckJson:
    """Audit H-3: `boxmunge check <project> --json` for MCP/agent consumption."""

    def _write_project(self, paths: BoxPaths, name: str, manifest: dict) -> None:
        import yaml
        paths.project_dir(name).mkdir(parents=True, exist_ok=True)
        paths.project_manifest(name).write_text(yaml.dump(manifest))
        paths.project_deploy_state(name).parent.mkdir(parents=True, exist_ok=True)
        paths.project_deploy_state(name).write_text('{"current_ref": "main"}')

    def test_json_output_parses(self, paths: BoxPaths, capsys, monkeypatch) -> None:
        from boxmunge.commands.check import cmd_check
        self._write_project(paths, "myapp", {
            "schema_version": 2, "id": "01TEST",
            "project": "myapp", "source": "bundle",
            "hosts": ["myapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        })
        monkeypatch.setattr(
            "boxmunge.commands.check.BoxPaths", lambda: paths,
        )
        with pytest.raises(SystemExit) as exc:
            cmd_check(["myapp", "--json"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload["project"] == "myapp"
        assert payload["exit_code"] == 0

    def test_json_output_includes_smoke_when_configured(
        self, paths: BoxPaths, capsys, monkeypatch,
    ) -> None:
        from boxmunge.commands.check import cmd_check
        self._write_project(paths, "myapp", {
            "schema_version": 2, "id": "01TEST",
            "project": "myapp", "source": "bundle",
            "hosts": ["myapp.example.com"],
            "services": {"web": {
                "port": 8080, "routes": [{"path": "/"}],
                "smoke": "boxmunge-scripts/smoke.sh",
            }},
        })
        monkeypatch.setattr(
            "boxmunge.commands.check.BoxPaths", lambda: paths,
        )
        with patch(
            "boxmunge.commands.check.run_smoke_in_container",
            return_value=SmokeResult(status="ok", message=""),
        ):
            with pytest.raises(SystemExit):
                cmd_check(["myapp", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["smoke"] == {"status": "ok", "message": ""}
        assert payload["exit_code"] == 0
