"""The unit-tier guard refuses a real docker spawn and fails the test."""
from __future__ import annotations

import subprocess
import sys

import pytest


def test_a_docker_spawn_is_refused_and_recorded(real_docker_guard) -> None:
    with pytest.raises(FileNotFoundError, match="real `docker` spawn was refused"):
        subprocess.run(["/usr/bin/docker", "compose", "ps"], capture_output=True)
    assert real_docker_guard.spawned == ["['/usr/bin/docker', 'compose', 'ps']"]
    real_docker_guard.spawned.clear()  # this test wanted it; teardown passes


def test_other_programs_still_run() -> None:
    out = subprocess.run([sys.executable, "-c", "print('ok')"], capture_output=True, text=True)
    assert out.stdout.strip() == "ok"


@pytest.mark.integration
def test_the_integration_tier_is_left_alone(real_docker_guard) -> None:
    assert subprocess.Popen is not None and real_docker_guard.spawned == []
    assert subprocess.Popen.__name__ == "Popen"


def test_docker_down_answers_every_docker_call_with_a_failure(docker_down) -> None:
    result = subprocess.run(["docker", "info"], capture_output=True, text=True)
    assert (result.returncode, result.stdout) == (1, "")
    assert docker_down == [["docker", "info"]]
