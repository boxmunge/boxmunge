# SPDX-License-Identifier: Apache-2.0
"""Run a backup or restore command inside a project service, killably.

Killing the `docker compose exec` client (on a timeout, or when boxmunge is
itself interrupted) does not stop what it started inside the container. A
hung pg_dump left running keeps its database locks and blocks the next
restore, and nightly runs would pile up more of them. So every command run
here carries a unique environment variable, inherited by all of its
processes, and on timeout or interruption those processes are found by it
and killed. That needs only sh, grep and /proc in the image, which a
command run with `sh -c` already implies.
"""

from __future__ import annotations

import secrets
import subprocess
from pathlib import Path
from typing import Any

_ID_VAR = "BOXMUNGE_EXEC_ID"
_STOP_SCRIPT = f"""
left() {{
  for d in /proc/[0-9]*; do
    grep -q "{_ID_VAR}=$1" "$d/environ" 2>/dev/null && return 0
  done
  return 1
}}
for d in /proc/[0-9]*; do
  grep -q "{_ID_VAR}=$1" "$d/environ" 2>/dev/null && kill -KILL "${{d#/proc/}}" 2>/dev/null
done
for i in 1 2 3 4 5; do left "$1" || exit 0; sleep 1; done
echo "processes still running after SIGKILL" >&2
exit 1
"""
_STOP_TIMEOUT = 60


class ServiceCommandTimeout(Exception):
    """The command overran its budget. ``stop_error`` is None if it was killed."""

    def __init__(self, timeout: float, stop_error: str | None) -> None:
        self.timeout = timeout
        self.stop_error = stop_error
        if stop_error is None:
            outcome = "it was stopped inside the container"
        else:
            outcome = (f"stopping it inside the container FAILED ({stop_error}), "
                       "so it may still be running there")
        super().__init__(f"timed out after {timeout}s; {outcome}")


def _exec(project_name: str, service: str, argv: list[str], env: str | None = None) -> list[str]:
    cmd = ["docker", "compose", "-f", "compose.yml", "-p", project_name, "exec", "-T"]
    if env is not None:
        cmd += ["-e", env]
    return cmd + [service, *argv]


def _stop(project_dir: Path, project_name: str, service: str, exec_id: str) -> str | None:
    """Kill the command's processes in the container; None, or why it failed."""
    cmd = _exec(project_name, service, ["sh", "-c", _STOP_SCRIPT, "boxmunge-stop", exec_id])
    try:
        result = subprocess.run(cmd, cwd=project_dir, capture_output=True,
                                text=True, timeout=_STOP_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError) as e:
        return str(e)
    if result.returncode != 0:
        return result.stderr.strip() or f"exit {result.returncode}"
    return None


def run_in_service(
    project_dir: Path, project_name: str, service: str, command: str,
    *, timeout: float, **run_kwargs: Any,
) -> subprocess.CompletedProcess:
    """``sh -c command`` in the service, bounded by ``timeout``.

    Raises ServiceCommandTimeout when it overruns, after killing it in the
    container. If boxmunge is interrupted meanwhile, the command is killed
    there too before the interruption propagates.
    """
    exec_id = secrets.token_hex(16)
    cmd = _exec(project_name, service, ["sh", "-c", command], env=f"{_ID_VAR}={exec_id}")
    try:
        return subprocess.run(cmd, cwd=project_dir, timeout=timeout, **run_kwargs)
    except subprocess.TimeoutExpired as e:
        raise ServiceCommandTimeout(
            timeout, _stop(project_dir, project_name, service, exec_id)) from e
    except OSError:
        raise  # nothing started
    except BaseException:
        _stop(project_dir, project_name, service, exec_id)
        raise
