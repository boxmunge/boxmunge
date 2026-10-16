"""Docker Compose >= 2.24 is required: older releases mis-read \\' in
single-quoted env-file values, which is how secrets are stored.

install.sh and compose_version.py each check it; one table drives both, so
the two parse every output the same way.
"""
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

# (exact stdout of `docker compose version --short`, verdict)
CASES = [
    ("2.24.0\n", "ok"),
    ("v2.24.0\n", "ok"),
    ("5.1.3\n", "ok"),
    ("2.26.1-4\n", "ok"),
    ("2.29.2-desktop.1\n", "ok"),
    ("2.40.3+ds1-0ubuntu1~24.04.1\n", "ok"),
    ("2.24.0\r\n", "ok"),            # whitespace is trimmed
    ("  2.25.0  \n", "ok"),
    ("3.0.0\n", "ok"),
    ("2.100.0\n", "ok"),
    ("2.23.3\n", "old"),
    ("v2.20.2\n", "old"),
    ("2.9.0\n", "old"),
    ("1.29.2\n", "old"),
    ("2.24.0-rc.1\n", "ok"),         # suffix ignored: 2.24.0 itself is supported
    ("", "unreadable"),
    ("\n", "unreadable"),
    ("garbage\n", "unreadable"),
    ("2.24\n", "unreadable"),
    ("2.24.0.1\n", "unreadable"),
    ("WARNING: something\n2.24.0\n", "unreadable"),
    ("2.24.0\nWARNING: something\n", "unreadable"),
    ("2.24.0-x y\n", "unreadable"),
    ("Docker Compose version v2.24.0\n", "unreadable"),
]


def _python_verdict(monkeypatch, out: str) -> tuple[str, str]:
    def fake_run(cmd, **kwargs):
        assert cmd == ["docker", "compose", "version", "--short"]
        return subprocess.CompletedProcess(cmd, 0, stdout=out.encode(), stderr=b"")
    with monkeypatch.context() as m:
        m.setattr(compose_version.subprocess, "run", fake_run)
        problem = compose_version_problem()
    if problem is None:
        return "ok", ""
    return ("old" if "is older than" in problem else
            "unreadable" if "could not read" in problem else "other"), problem


def _bash_verdict(tmp_path: Path, out: str, rc: int = 0) -> tuple[str, str]:
    fake = tmp_path / "bin" / "docker"
    fake.parent.mkdir(exist_ok=True)
    fake.write_text(f'#!/bin/sh\nprintf "%s" "$FAKE_COMPOSE_OUT"\nexit {rc}\n')
    fake.chmod(0o755)
    script = (
        "set -euo pipefail\n"
        f"eval \"$(sed -n '/^MIN_COMPOSE_VERSION=/p; /^require_compose_version() {{/,/^}}/p' {INSTALL_SH})\"\n"
        "require_compose_version\necho OK\n"
    )
    env = {**os.environ, "PATH": f"{fake.parent}:{os.environ['PATH']}", "FAKE_COMPOSE_OUT": out}
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    if result.returncode == 0 and result.stdout == "OK\n":
        return "ok", ""
    assert result.returncode == 1 and "OK" not in result.stdout, result
    err = result.stderr
    return ("old" if "is older than" in err else
            "unreadable" if "could not read" in err else "other"), err


@pytest.mark.parametrize("out,verdict", CASES)
def test_python_and_install_sh_agree(tmp_path: Path, monkeypatch, out: str, verdict: str) -> None:
    py, py_msg = _python_verdict(monkeypatch, out)
    sh, sh_msg = _bash_verdict(tmp_path, out)
    assert (py, sh) == (verdict, verdict), (py_msg, sh_msg)
    if verdict == "old":
        assert "apt-get install --only-upgrade docker-compose-plugin" in py_msg
        assert "apt-get install --only-upgrade docker-compose-plugin" in sh_msg


@pytest.mark.parametrize("out", ["garbage\n", "2.24\n", "WARNING: x\n2.24.0\n"])
def test_unreadable_output_is_shown(tmp_path: Path, monkeypatch, out: str) -> None:
    first_word = out.split()[0]
    assert first_word in _python_verdict(monkeypatch, out)[1]
    assert first_word in _bash_verdict(tmp_path, out)[1]


def test_failing_command_is_an_error_in_both(tmp_path: Path, monkeypatch) -> None:
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout=b"", stderr=b"no such plugin")
    with monkeypatch.context() as m:
        m.setattr(compose_version.subprocess, "run", fake_run)
        assert "failed (exit 1): no such plugin" in compose_version_problem()
    verdict, msg = _bash_verdict(tmp_path, "", rc=1)
    assert "failed" in msg


def test_install_sh_minimum_matches_the_python_one() -> None:
    match = re.search(r'^MIN_COMPOSE_VERSION="([0-9.]+)"$', INSTALL_SH.read_text(), re.M)
    assert match and match.group(1) == ".".join(map(str, MIN_COMPOSE_VERSION))
