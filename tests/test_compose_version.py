"""Docker Compose >= 2.24 is required: older releases mis-read \\' in
single-quoted env-file values, which is how secrets are stored."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from boxmunge import compose_version
from boxmunge.compose_version import MIN_COMPOSE_VERSION, compose_version_problem

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "install.sh"


def _fake_compose(monkeypatch, stdout: str, returncode: int = 0) -> None:
    def fake_run(cmd, **kwargs):
        assert cmd == ["docker", "compose", "version", "--short"]
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="boom")
    monkeypatch.setattr(compose_version.subprocess, "run", fake_run)


@pytest.mark.parametrize("out", ["2.24.0\n", "v2.29.7\n", "5.1.3\n", "2.40.0-desktop.1\n"])
def test_supported_versions_pass(monkeypatch, out: str) -> None:
    _fake_compose(monkeypatch, out)
    assert compose_version_problem() is None


@pytest.mark.parametrize("out", ["2.23.3\n", "v2.20.2\n", "2.17.0\n", "1.29.2\n"])
def test_old_versions_are_reported_with_the_fix(monkeypatch, out: str) -> None:
    _fake_compose(monkeypatch, out)
    problem = compose_version_problem()
    assert "older than 2.24.0" in problem
    assert "apt-get install --only-upgrade docker-compose-plugin" in problem


def test_unreadable_output_is_a_problem_not_a_pass(monkeypatch) -> None:
    _fake_compose(monkeypatch, "", returncode=1)
    assert "exit 1" in compose_version_problem()


def test_install_sh_minimum_matches_the_python_one() -> None:
    match = re.search(r'^MIN_COMPOSE_VERSION="([0-9.]+)"$', INSTALL_SH.read_text(), re.M)
    assert match and match.group(1) == ".".join(map(str, MIN_COMPOSE_VERSION))


def _run_install_check(tmp_path: Path, version_output: str, rc: int = 0):
    fake = tmp_path / "bin" / "docker"
    fake.parent.mkdir()
    fake.write_text(f"#!/bin/sh\nprintf '%s\\n' '{version_output}'\nexit {rc}\n")
    fake.chmod(0o755)
    script = (
        "set -euo pipefail\n"
        f"eval \"$(sed -n '/^MIN_COMPOSE_VERSION=/p; /^require_compose_version() {{/,/^}}/p' {INSTALL_SH})\"\n"
        "require_compose_version\necho OK\n"
    )
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          env={**os.environ, "PATH": f"{fake.parent}:{os.environ['PATH']}"})


@pytest.mark.parametrize("out", ["2.24.0", "v2.29.7", "5.1.3", "2.40.0-desktop.1"])
def test_install_sh_accepts_supported_versions(tmp_path: Path, out: str) -> None:
    result = _run_install_check(tmp_path, out)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "OK\n"


@pytest.mark.parametrize("out,rc", [("2.23.3", 0), ("v2.20.2", 0), ("2.9.0", 0),
                                    ("garbage", 0), ("", 1)])
def test_install_sh_refuses_old_or_missing_compose(tmp_path: Path, out: str, rc: int) -> None:
    result = _run_install_check(tmp_path, out, rc)
    assert result.returncode == 1
    assert "ERROR:" in result.stderr and "OK" not in result.stdout
