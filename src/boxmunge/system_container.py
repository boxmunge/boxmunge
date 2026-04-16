# SPDX-License-Identifier: Apache-2.0
"""Abstraction for executing commands inside the boxmunge-system container.

The system container encapsulates risky tooling (age, rclone) for
blast-radius containment. Commands that previously ran on the host
now exec into this container instead.
"""

import subprocess
from typing import Any

CONTAINER_NAME = "boxmunge-system"
_DEFAULT_TIMEOUT = 600  # 10 minutes (backup dumps can be large)


class SystemContainerError(Exception):
    """Raised when a system container operation fails."""


def ensure_system_container() -> bool:
    """Check if the system container is running. Returns True if running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", CONTAINER_NAME],
            capture_output=True, text=True, check=False, timeout=10,
        )
        return result.returncode == 0 and "running" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def system_exec(
    cmd: list[str],
    timeout: int = _DEFAULT_TIMEOUT,
    stdin: bytes | None = None,
    capture: bool = True,
) -> subprocess.CompletedProcess[Any]:
    """Execute a command inside the boxmunge-system container.

    Raises SystemContainerError on failure or timeout.
    """
    docker_cmd = ["docker", "exec"]
    if stdin is not None:
        docker_cmd.append("-i")
    docker_cmd.append(CONTAINER_NAME)
    docker_cmd.extend(cmd)

    try:
        return subprocess.run(
            docker_cmd,
            input=stdin,
            capture_output=capture,
            text=stdin is None,  # text mode when no binary stdin
            check=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise SystemContainerError(
            f"Command timed out after {timeout}s: {' '.join(cmd)}"
        ) from e
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        raise SystemContainerError(
            f"Command failed in system container: {' '.join(cmd)}\n{stderr.strip()}"
        ) from e
