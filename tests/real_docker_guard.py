"""Unit-tier guard: no test spawns the real docker CLI.

A unit test that reaches the Docker daemon depends on what that daemon
holds (another agent's `myapp`, a CI box with no Docker) and can act on
it. Outside the integration tier every `docker` spawn is refused, as if
the CLI were missing, and the test fails at teardown naming the command,
even when the code under test swallowed the refusal.
"""
from __future__ import annotations

import os
import subprocess

import pytest

_REAL_POPEN = subprocess.Popen


class RealDockerGuard:
    def __init__(self) -> None:
        self.spawned: list[str] = []


def _program(args) -> str:
    if isinstance(args, (str, bytes)):
        args = os.fsdecode(args).split()
    else:
        args = [os.fsdecode(a) if isinstance(a, (str, bytes, os.PathLike)) else str(a)
                for a in args]
    return os.path.basename(args[0]) if args else ""


@pytest.fixture(autouse=True)
def real_docker_guard(request, monkeypatch):
    guard = RealDockerGuard()
    if request.node.get_closest_marker("integration"):
        yield guard
        return

    class Guarded(_REAL_POPEN):
        def __init__(self, args, *a, **k):
            if _program(args) == "docker":
                guard.spawned.append(repr(args))
                raise FileNotFoundError(
                    "unit tier: a real `docker` spawn was refused; stub the docker seam "
                    "or mark the test integration")
            super().__init__(args, *a, **k)

    monkeypatch.setattr(subprocess, "Popen", Guarded)
    yield guard
    if guard.spawned:
        pytest.fail("the test spawned the real docker CLI (stub the seam, or mark it "
                    "integration):\n  " + "\n  ".join(guard.spawned), pytrace=False)


@pytest.fixture
def docker_down(monkeypatch, real_docker_guard):
    """Opt-in for a test whose code probes the docker CLI incidentally
    (doctor, health, the TUI host panel, a Caddy validate): every docker
    call through subprocess.run fails (exit 1, no output), as when the
    daemon is not running. Returns the calls made."""
    calls: list[list[str]] = []
    real_run = subprocess.run

    def run(args, *a, **k):
        if _program(args) != "docker":
            return real_run(args, *a, **k)
        calls.append(list(args) if not isinstance(args, (str, bytes)) else [args])
        return subprocess.CompletedProcess(args, 1, "" if k.get("text") else b"",
                                           "" if k.get("text") else b"")

    monkeypatch.setattr(subprocess, "run", run)
    return calls
