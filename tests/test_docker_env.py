# SPDX-License-Identifier: Apache-2.0
"""Every docker and compose subprocess runs in the one fixed environment.

Compose interpolates `${VAR}` from the process environment, so a docker
call that inherited its caller's environment could run a different model
from the one validated (see docker_run.DOCKER_ENV). The integration test
tests/integration/test_compose_env.py proves the resolved models match.
These tests prove no spawn escapes the fixed environment: every process
spawn in src/boxmunge passes env=docker_env() or is classified as not
docker, wherever its argv was built.
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
    "subprocess": {"run", "Popen", "call", "check_call", "check_output",
                   "getoutput", "getstatusoutput"},
    "os": {"system", "popen", "execv", "execve", "execvp", "execvpe", "execl",
           "execle", "execlp", "execlpe", "spawnv", "spawnve", "spawnvp",
           "spawnvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe",
           "posix_spawn", "posix_spawnp"},
    "asyncio": {"create_subprocess_exec", "create_subprocess_shell"},
    "pty": {"spawn"},
}
_SPAWN_MODULES = set(_SPAWNERS) | {"asyncio.subprocess"}

# Every process spawn in src/boxmunge either passes env=docker_env() or is
# listed here, keyed (file, function, program), with why it is not docker.
# A new spawn site fails test_every_spawn_is_classified until it is one or
# the other. "?" is a program the scan cannot read from the source.
NOT_DOCKER = {
    ("as_deploy.py", "run_as_deploy", "?"): "the manifest's pre_deploy hook, and git in the project's repo or the slot's clone",
    ("commands/add_git_project_cmd.py", "run_add_git_project", "git"): "clones the project repo",
    ("commands/auto_update_cmd.py", "run_auto_update", "?"): "execs the upgrade shim, whose boxmunge-server scrubs its own docker calls",
    ("commands/doctor.py", "run_doctor", "systemctl"): "reads timer state",
    ("commands/logs.py", "_show_host_logs", "journalctl"): "reads the journal",
    ("cve/scanner.py", "refresh_db", "trivy"): "trivy DB download; never reads project compose files, needs HOME for its cache",
    ("cve/scanner.py", "scan_image", "trivy"): "trivy scans an image from the daemon; never reads project compose files",
    ("health_checks/hardening.py", "_run", "?"): "host hardening probes (ufw, systemctl, sshd) with an sbin PATH",
    ("mcp_tools.py", "run_subprocess_tool", "?"): "runs the upgrade shim argv",
    ("os_updates.py", "_systemctl", "systemctl"): "reads apt timer and unit state",
    ("sftp_receive.py", "main", "?"): "execs OpenSSH sftp-server",
    ("shell.py", "handle_scp_upload", "/usr/bin/scp"): "receives an upload into the inbox",
    ("shell.py", "run_command", "boxmunge-server"): "boxmunge-server scrubs its own docker calls",
    ("shell.py", "_run_upgrade", "?"): "runs the upgrade shim or boxmunge-server upgrade",
    ("version.py", "get_build_version", "git"): "reads the source commit",
}

PARENT_ENVS = [
    {"PATH": "/usr/bin:/bin", "HOME": "/home/deploy", "USER": "deploy",
     "SSH_CONNECTION": "192.0.2.10 50022 192.0.2.20 922"},
    {"PATH": "/usr/sbin:/usr/bin", "HOME": "/root", "INVOCATION_ID": "6f1c0a9e",
     "JOURNAL_STREAM": "8:41234", "COMPOSE_PROFILES": "debug",
     "DOCKER_HOST": "tcp://192.0.2.99:2375"},
]


def _is_spawn(call: ast.Call) -> bool:
    f = call.func
    if not isinstance(f, ast.Attribute):
        return False
    if f.attr in ("subprocess_exec", "subprocess_shell"):  # loop.subprocess_*
        return True
    return isinstance(f.value, ast.Name) and f.attr in _SPAWNERS.get(f.value.id, ())


def _program(node: ast.AST | None, func: ast.AST) -> str:
    """argv[0] as written in the source, or "?"."""
    if isinstance(node, ast.Starred):
        node = node.value
    if isinstance(node, ast.BinOp):
        node = node.left
    if isinstance(node, ast.List) and node.elts:
        first = node.elts[0]
        return first.value if isinstance(first, ast.Constant) else "?"
    if isinstance(node, ast.Call):
        f = node.func
        name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
        return "docker" if name == "compose_command" else "?"
    if isinstance(node, ast.Name):
        for n in ast.walk(func):
            if (isinstance(n, ast.Assign) and n.value is not node and any(
                    isinstance(t, ast.Name) and t.id == node.id for t in n.targets)):
                return _program(n.value, func)
    return "?"


def _uses_docker_env(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "env":
            v = kw.value
            return (isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                    and v.func.id == "docker_env")
    return False


def _spawn_sites() -> list[tuple[tuple[str, str, str], bool, int]]:
    """((file, function, program), passes docker_env, line) per spawn."""
    sites = []
    for path in sorted(SRC.rglob("*.py")):
        rel = str(path.relative_to(SRC))
        tree = ast.parse(path.read_text())
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for call in ast.walk(func):
                if isinstance(call, ast.Call) and _is_spawn(call):
                    argv = call.args[0] if call.args else None
                    key = (rel, func.name, _program(argv, func))
                    sites.append((key, _uses_docker_env(call), call.lineno))
    return sites


def test_every_spawn_is_classified() -> None:
    unclassified = [f"{k[0]}:{line} {k[1]}() runs {k[2]!r}"
                    for k, scrubbed, line in _spawn_sites()
                    if not scrubbed and k not in NOT_DOCKER]
    assert not unclassified, (
        "process spawns that neither pass env=docker_env() nor are listed in "
        f"NOT_DOCKER with a reason: {unclassified}"
    )


def test_docker_is_never_classified_as_not_docker() -> None:
    assert not [k for k in NOT_DOCKER if k[2] == "docker"]


def test_not_docker_entries_are_current() -> None:
    present = {k for k, scrubbed, _ in _spawn_sites() if not scrubbed}
    stale = sorted(set(NOT_DOCKER) - present)
    assert not stale, f"NOT_DOCKER lists spawns that no longer exist: {stale}"


def test_spawn_functions_are_not_imported_under_other_names() -> None:
    """The scan matches `subprocess.run(...)` etc.; an aliased import would hide one."""
    aliased = []
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom) and node.module in _SPAWN_MODULES:
                names = {a.name for a in node.names}
                if node.module != "os" or names & _SPAWNERS["os"]:
                    aliased.append(f"{path.relative_to(SRC)}:{node.lineno}")
            if isinstance(node, ast.Import):
                aliased += [f"{path.relative_to(SRC)}:{node.lineno}" for a in node.names
                            if a.name in _SPAWN_MODULES and a.asname]
    assert not aliased, f"import the module, not its spawn functions: {aliased}"


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
