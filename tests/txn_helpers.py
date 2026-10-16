"""Helpers for install-transaction tests: docker off, hooks, crashes, backups."""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Callable
from unittest.mock import patch

from tests.bundle_helpers import manifest_text


@contextmanager
def docker_off():
    """Container starts and Caddy reloads succeed without Docker."""
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.commands.deploy.caddy_reload"):
        yield up


def hook_manifest(command: str, backup: str = "none") -> str:
    # Quoted: YAML would read a bare `false` or `true` as a boolean.
    return manifest_text(backup=backup) + f"deploy:\n  pre_deploy: '{command}'\n"


def flaky_hook(tmp: Path, failures: int = 1) -> str:
    """A pre_deploy command that fails `failures` times, then succeeds; its
    run count is in tmp/hook-runs."""
    script = tmp / "flaky.sh"
    script.write_text(
        f'n=$(cat {tmp}/hook-runs 2>/dev/null || echo 0); n=$((n+1)); '
        f'echo $n > {tmp}/hook-runs; [ "$n" -gt {failures} ]\n')
    return f"sh {script}"


def hook_runs(tmp: Path) -> int:
    path = tmp / "hook-runs"
    return int(path.read_text()) if path.exists() else 0


def crash_at(point: str, fn: Callable[[], object]) -> int:
    """Run fn in a forked child that dies at `point`; return its exit code
    (137 when the point was reached, 0 when fn returned without reaching it)."""
    from boxmunge.crashpoint import CRASH_ENV
    pid = os.fork()
    if pid == 0:
        os.environ[CRASH_ENV] = point
        try:
            fn()
        finally:
            os._exit(0)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


@contextmanager
def fake_backups(taken: list[dict]):
    """backup_locked records the manifest it was given and writes a snapshot."""
    def fake(project_name, paths_, kind=None, manifest=None):
        taken.append(manifest)
        snap = paths_.project_backups(project_name) / f"{project_name}-p{len(taken)}.tar.gz.age"
        snap.parent.mkdir(parents=True, exist_ok=True)
        snap.write_text("snapshot")
        return 0
    with patch("boxmunge.commands.backup_cmd.backup_locked", fake):
        yield
