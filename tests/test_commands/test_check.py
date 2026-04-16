"""Tests for boxmunge check command — health checking logic."""

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
        assert "pre-registered" in captured.out
        assert "boxmunge deploy myapp" in captured.out
