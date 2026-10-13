# SPDX-License-Identifier: Apache-2.0
"""Abstraction for executing commands inside the boxmunge-system container.

The system container encapsulates risky tooling (age, rclone) for
blast-radius containment. Commands that previously ran on the host
now exec into this container instead.
"""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxmunge.paths import BoxPaths

CONTAINER_NAME = "boxmunge-system"
_DEFAULT_TIMEOUT = 600  # 10 minutes (backup dumps can be large)


class SystemContainerError(Exception):
    """Raised when a system container operation fails."""


@dataclass(frozen=True)
class Mount:
    """One bind mount of the system container (see system/compose.yml)."""

    host: Path
    container: str
    directory: bool


def system_mounts(paths: BoxPaths) -> tuple[Mount, ...]:
    """The system container's mount table, derived from the same BoxPaths.

    Must match the volumes in system/compose.yml. Host sides are resolved so
    that a symlinked root (macOS /var -> /private/var) still prefix-matches.
    """
    return (
        Mount(paths.projects.resolve(), "/projects", directory=True),
        Mount(paths.backup_key.resolve(), "/config/backup.key", directory=False),
    )


def _describe_mounts(mounts: tuple[Mount, ...]) -> str:
    return ", ".join(f"{m.host} -> {m.container}" for m in mounts)


def container_path(host_path: Path, paths: BoxPaths) -> str:
    """Translate a host path to the path the system container sees.

    A prefix match on the resolved mount roots: a directory mount maps
    everything beneath it, a file mount maps only that file. Anything else
    is invisible to the container, so raise instead of guessing.
    """
    mounts = system_mounts(paths)
    resolved = host_path.resolve()
    for mount in mounts:
        if mount.directory and resolved.is_relative_to(mount.host):
            rel = resolved.relative_to(mount.host).as_posix()
            return mount.container if rel == "." else f"{mount.container}/{rel}"
        if not mount.directory and resolved == mount.host:
            return mount.container
    raise SystemContainerError(
        f"Path {host_path} is outside the system container's mounts "
        f"({_describe_mounts(mounts)}). age and rclone run inside "
        f"{CONTAINER_NAME} and can only read or write paths under these mounts."
    )


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
