# SPDX-License-Identifier: Apache-2.0
"""Run docker and compose commands; a failure carries the command's stderr.

boxmunge.docker builds the commands. This module runs them, so every
DockerError for a failed or timed-out command says why it failed: the tail
of the command's stderr, which is where Compose writes its errors.

Every docker command runs in DOCKER_ENV, never the caller's environment
(see docker_env).
"""
from __future__ import annotations

import subprocess
import sys
import threading
from collections import deque
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

DEFAULT_TIMEOUT = 120

# Compose interpolates `${VAR}` from the process environment, so the
# environment is part of the model Compose runs. boxmunge is called from a
# deploy user's SSH session, from root systemd timers (INVOCATION_ID,
# JOURNAL_STREAM, ...), via sudo and from MCP; inheriting any of those let
# a compose file validate as one model and run as another. Every docker
# and compose command boxmunge makes runs in exactly this environment.
#
# HOME is deliberately absent. ${HOME} then resolves to nothing for every
# caller, and the docker CLI finds its config directory (contexts, plugins,
# registry credentials) from the password database for the user it runs
# as: deploy's ~/.docker for deploy-run commands, /root/.docker for root.
# A shared, fixed DOCKER_CONFIG would need to be writable by deploy (buildx
# keeps state there), and a deploy-writable directory whose plugins and
# credential helpers root executes is a path from deploy to root.
# Project values belong in the project's own `.env`, which Compose reads
# itself.
DOCKER_ENV: Mapping[str, str] = MappingProxyType({
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
})


def docker_env() -> dict[str, str]:
    """The environment for every docker and compose subprocess (a fresh copy)."""
    return dict(DOCKER_ENV)


class DockerError(Exception):
    """Raised when a Docker/Compose operation fails."""


# A failed command's DockerError ends with the last lines of its stderr:
# enough for the cause (compose prints progress first, the error last),
# short enough for a log line and an alert.
_STDERR_TAIL_LINES = 20
_STDERR_MAX_CHARS = 2000


def _as_text(stream: str | bytes | None) -> str:
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return stream or ""


def _stderr_tail(stderr: str) -> str:
    lines = [line.rstrip() for line in stderr.splitlines() if line.strip()]
    tail = "\n".join(lines[-_STDERR_TAIL_LINES:])
    if len(tail) > _STDERR_MAX_CHARS:
        tail = "..." + tail[-_STDERR_MAX_CHARS:]
    return tail


def _command_error(cmd: list[str], what: str, stderr: str | bytes | None) -> DockerError:
    tail = _stderr_tail(_as_text(stderr))
    return DockerError(f"Command {what}: {' '.join(cmd)}\n{tail or '(no stderr output)'}")


def _run_streaming(
    cmd: list[str], cwd: Path | None, timeout: int,
) -> subprocess.CompletedProcess:
    """Run with stdout inherited and stderr both shown live and kept.

    Compose writes progress and errors to stderr. An operator watching a
    deploy still sees it as it happens, and a failure still knows its cause.
    """
    kept: deque[str] = deque(maxlen=_STDERR_TAIL_LINES * 5)
    proc = subprocess.Popen(cmd, cwd=cwd, stderr=subprocess.PIPE, text=True,
                            errors="replace", env=docker_env())
    assert proc.stderr is not None

    def pump() -> None:
        for line in proc.stderr:
            sys.stderr.write(line)
            sys.stderr.flush()
            kept.append(line)

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        reader.join(timeout=5)
        raise subprocess.TimeoutExpired(cmd, timeout, stderr="".join(kept)) from None
    reader.join()
    return subprocess.CompletedProcess(cmd, proc.returncode, None, "".join(kept))


def run(
    cmd: list[str],
    cwd: Path | None = None,
    capture: bool = False,
    check: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> subprocess.CompletedProcess:
    """Run a command, optionally capturing stdout. Raises DockerError on failure.

    stderr is always kept, so every DockerError for a failed or timed-out
    command ends with the tail of what the command printed there.
    """
    try:
        if capture:
            result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                                    check=False, timeout=timeout, env=docker_env())
        else:
            result = _run_streaming(cmd, cwd, timeout)
    except subprocess.TimeoutExpired as e:
        raise _command_error(cmd, f"timed out after {timeout}s", e.stderr) from e
    if check and result.returncode != 0:
        raise _command_error(cmd, f"failed (exit {result.returncode})", result.stderr)
    return result
