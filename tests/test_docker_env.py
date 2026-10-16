# SPDX-License-Identifier: Apache-2.0
"""Every docker and compose subprocess runs in the one fixed environment.

Compose interpolates `${VAR}` from the process environment, so a docker
call that inherited its caller's environment could run a different model
from the one validated (see docker_run.DOCKER_ENV). The integration test
tests/integration/test_compose_env.py proves the resolved models match;
these tests prove no call site escapes the fixed environment.
"""
from __future__ import annotations

import ast
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from boxmunge import docker_run

SRC = Path(__file__).resolve().parents[1] / "src" / "boxmunge"
_SPAWNERS = {
    ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
    ("subprocess", "check_call"), ("subprocess", "check_output"),
    ("asyncio", "create_subprocess_exec"),
}

PARENT_ENVS = [
    {"PATH": "/usr/bin:/bin", "HOME": "/home/deploy", "USER": "deploy",
     "SSH_CONNECTION": "192.0.2.10 50022 192.0.2.20 922"},
    {"PATH": "/usr/sbin:/usr/bin", "HOME": "/root", "INVOCATION_ID": "6f1c0a9e",
     "JOURNAL_STREAM": "8:41234", "COMPOSE_PROFILES": "debug",
     "DOCKER_HOST": "tcp://192.0.2.99:2375"},
]


def _spawner(call: ast.Call) -> bool:
    f = call.func
    return (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
            and (f.value.id, f.attr) in _SPAWNERS)


def _builds_docker(node: ast.AST | None) -> bool:
    """A list literal starting with "docker", or a compose_command(...) call."""
    if isinstance(node, ast.Starred):
        node = node.value
    if isinstance(node, ast.List):
        first = node.elts[0] if node.elts else None
        return isinstance(first, ast.Constant) and first.value == "docker"
    if isinstance(node, ast.Call):
        f = node.func
        name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
        return name == "compose_command"
    return False


def _docker_spawns(tree: ast.Module) -> list[ast.Call]:
    """Spawn calls whose argv is (or is a local name bound to) a docker command."""
    found = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        docker_names = {
            t.id for n in ast.walk(func) if isinstance(n, ast.Assign)
            and _builds_docker(n.value) for t in n.targets if isinstance(t, ast.Name)
        }
        for call in ast.walk(func):
            if not (isinstance(call, ast.Call) and _spawner(call) and call.args):
                continue
            argv = call.args[0]
            inner = argv.value if isinstance(argv, ast.Starred) else argv
            if _builds_docker(argv) or (isinstance(inner, ast.Name)
                                         and inner.id in docker_names):
                found.append(call)
    return found


def _uses_docker_env(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "env":
            v = kw.value
            return (isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                    and v.func.id == "docker_env")
    return False


def test_every_docker_subprocess_passes_the_fixed_env() -> None:
    sites, missing = 0, []
    for path in sorted(SRC.rglob("*.py")):
        for call in _docker_spawns(ast.parse(path.read_text())):
            sites += 1
            if not _uses_docker_env(call):
                missing.append(f"{path.relative_to(SRC)}:{call.lineno}")
    assert not missing, f"docker subprocess without env=docker_env(): {missing}"
    # Guards the scan itself: it must keep finding the direct call sites.
    assert sites >= 20, f"scan found only {sites} docker call sites"


def test_docker_env_is_fixed_and_minimal() -> None:
    env = docker_run.docker_env()
    assert set(env) == {"PATH", "LANG"}
    env["X"] = "1"
    assert "X" not in docker_run.docker_env()


@pytest.mark.parametrize("parent", PARENT_ENVS)
def test_captured_run_ignores_the_caller_environment(monkeypatch, parent) -> None:
    for key, value in parent.items():
        monkeypatch.setenv(key, value)
    done = subprocess.CompletedProcess([], 0, "", "")
    with patch("boxmunge.docker_run.subprocess.run", return_value=done) as run:
        docker_run.run(["docker", "compose", "config"], capture=True)
    assert run.call_args.kwargs["env"] == dict(docker_run.DOCKER_ENV)


@pytest.mark.parametrize("parent", PARENT_ENVS)
def test_streaming_run_ignores_the_caller_environment(monkeypatch, parent) -> None:
    for key, value in parent.items():
        monkeypatch.setenv(key, value)
    proc = MagicMock(returncode=0, stderr=iter(()))
    with patch("boxmunge.docker_run.subprocess.Popen", return_value=proc) as popen:
        docker_run.run(["docker", "compose", "up", "-d"])
    assert popen.call_args.kwargs["env"] == dict(docker_run.DOCKER_ENV)
