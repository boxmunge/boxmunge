# SPDX-License-Identifier: Apache-2.0
"""A failed docker command's DockerError carries its stderr.

container-update logged "Command failed: docker compose ... pull" for months
with no cause, because commands run without capture had their stderr go
straight to the journal. These run real (non-docker) processes through
docker._run, so they exercise the real capture path.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.docker import compose_pull
from boxmunge.docker_run import DockerError
from boxmunge.docker_run import run as _run


def _script(tmp_path: Path, body: str) -> list[str]:
    """A command whose argv does not contain what it prints."""
    script = tmp_path / "cmd.sh"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)
    return [str(script)]


@pytest.mark.parametrize("capture", [False, True])
def test_failure_carries_stderr_and_exit_status(tmp_path, capture):
    cmd = _script(tmp_path, "echo 'pull access denied for localname' >&2; exit 3")
    with pytest.raises(DockerError) as exc:
        _run(cmd, capture=capture)
    message = str(exc.value)
    assert "Command failed" in message and "exit 3" in message
    assert "pull access denied for localname" in message


def test_uncaptured_stderr_is_still_shown_live(capfd):
    with pytest.raises(DockerError):
        _run(["sh", "-c", "echo progress >&2; echo out; exit 1"])
    captured = capfd.readouterr()
    assert "progress" in captured.err and "out" in captured.out


def test_uncaptured_success_returns_normally(capfd):
    result = _run(["sh", "-c", "echo fine >&2"])
    assert result.returncode == 0
    assert "fine" in capfd.readouterr().err


def test_check_false_does_not_raise():
    assert _run(["sh", "-c", "exit 2"], capture=True, check=False).returncode == 2


@pytest.mark.parametrize("capture", [False, True])
def test_timeout_carries_stderr_so_far(tmp_path, capture):
    cmd = _script(tmp_path, "echo 'waiting for registry' >&2; exec sleep 5")
    with pytest.raises(DockerError) as exc:
        _run(cmd, capture=capture, timeout=1)
    message = str(exc.value)
    assert "timed out after 1s" in message
    assert "waiting for registry" in message


def test_long_stderr_is_trimmed_to_its_tail():
    script = "for i in $(seq 1 200); do echo line$i >&2; done; exit 1"
    with pytest.raises(DockerError) as exc:
        _run(["sh", "-c", script])
    message = str(exc.value)
    assert "line200" in message and "line150" not in message
    assert len(message) < 2500


def test_empty_stderr_says_so():
    with pytest.raises(DockerError) as exc:
        _run(["sh", "-c", "exit 1"])
    assert "no stderr output" in str(exc.value)


def test_compose_pull_ignores_buildable_services():
    """`build:` plus a local `image:` name made pull ask Docker Hub for the
    local name ("pull access denied") and fail the update every day."""
    with patch("boxmunge.docker._run") as run:
        compose_pull(Path("/projects/myapp"), project_name="myapp")
    cmd = run.call_args[0][0]
    assert cmd[cmd.index("pull"):] == ["pull", "--ignore-buildable"]
