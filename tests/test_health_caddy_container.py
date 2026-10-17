"""health's caddy check: boxmunge-caddy must be the platform's own Caddy."""
from __future__ import annotations

import subprocess

import pytest

from boxmunge.commands import health_cmd


def _inspect(monkeypatch, stdout: str, returncode: int = 0) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")
    monkeypatch.setattr(health_cmd.subprocess, "run", run)
    return calls


def test_platform_caddy_healthy_is_ok(monkeypatch) -> None:
    calls = _inspect(monkeypatch, "healthy|caddy\n")
    check = health_cmd.check_caddy_container()
    assert check.status == "ok"
    assert calls[0][-1] == "boxmunge-caddy"
    assert '{{index .Config.Labels "com.docker.compose.project"}}' in calls[0][3]


@pytest.mark.parametrize("project", ["myapp", "", "caddy-staging"])
def test_a_squatting_container_is_an_error(monkeypatch, project) -> None:
    """CrowdSec follows the name: another project's container would be read as Caddy."""
    _inspect(monkeypatch, f"healthy|{project}\n")
    check = health_cmd.check_caddy_container()
    assert check.status == "error"
    assert f"compose project {project!r}" in check.detail
    assert "docker compose -f /opt/boxmunge/caddy/compose.yml up -d" in check.detail


def test_missing_container_is_an_error(monkeypatch) -> None:
    _inspect(monkeypatch, "", returncode=1)
    assert health_cmd.check_caddy_container().detail == "Caddy container not found"


def test_unhealthy_platform_caddy_warns(monkeypatch) -> None:
    _inspect(monkeypatch, "starting|caddy\n")
    check = health_cmd.check_caddy_container()
    assert (check.status, check.detail) == ("warn", "Caddy container status: starting")
