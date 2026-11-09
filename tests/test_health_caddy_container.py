"""health's caddy check: boxmunge-caddy must be the platform's own Caddy."""
from __future__ import annotations

import subprocess

import pytest

from boxmunge.commands import health_cmd


def _inspect(monkeypatch, stdout: str, returncode: int = 0,
             stderr: str = "") -> list[list[str]]:
    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(health_cmd.subprocess, "run", run)
    return calls


def test_platform_caddy_healthy_is_ok(monkeypatch) -> None:
    calls = _inspect(monkeypatch, "true|false|healthy|caddy\n")
    check = health_cmd.check_caddy_container()
    assert check.status == "ok"
    assert calls[0][-1] == "boxmunge-caddy"
    assert '{{index .Config.Labels "com.docker.compose.project"}}' in calls[0][3]


@pytest.mark.parametrize("project", ["myapp", "", "caddy-staging"])
def test_a_squatting_container_is_an_error(monkeypatch, project) -> None:
    """CrowdSec follows the name: another project's container would be read as Caddy."""
    _inspect(monkeypatch, f"true|false|healthy|{project}\n")
    check = health_cmd.check_caddy_container()
    assert check.status == "error"
    assert f"compose project {project!r}" in check.detail
    assert "docker compose -f /opt/boxmunge/caddy/compose.yml up -d" in check.detail


def test_missing_container_is_an_error(monkeypatch) -> None:
    _inspect(monkeypatch, "", returncode=1, stderr="Error: No such object: boxmunge-caddy")
    check = health_cmd.check_caddy_container()
    assert (check.status, check.detail) == ("error", "Caddy container not found")


def test_another_inspect_failure_warns(monkeypatch) -> None:
    """e.g. while container-update recreates it: not proof Caddy is down."""
    _inspect(monkeypatch, "", returncode=1, stderr="Error response from daemon: busy")
    check = health_cmd.check_caddy_container()
    assert check.status == "warn" and "busy" in check.detail


@pytest.mark.parametrize("state,word", [("false|false", "not running"),
                                        ("true|true", "restarting")])
def test_stopped_or_restarting_caddy_is_an_error(monkeypatch, state, word) -> None:
    _inspect(monkeypatch, f"{state}|unhealthy|caddy\n")
    check = health_cmd.check_caddy_container()
    assert check.status == "error" and word in check.detail


def test_unhealthy_platform_caddy_warns(monkeypatch) -> None:
    _inspect(monkeypatch, "true|false|starting|caddy\n")
    check = health_cmd.check_caddy_container()
    assert (check.status, check.detail) == ("warn", "Caddy container status: starting")


def test_running_but_unhealthy_caddy_warns(monkeypatch) -> None:
    _inspect(monkeypatch, "true|false|unhealthy|caddy\n")
    assert health_cmd.check_caddy_container().status == "warn"
