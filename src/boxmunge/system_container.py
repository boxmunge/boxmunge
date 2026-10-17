# SPDX-License-Identifier: Apache-2.0
"""Executing age and rclone inside the boxmunge-system container.

The system container encapsulates risky tooling (age, rclone) for
blast-radius containment. There is no host fallback: when the container
is missing, stopped, or mounted differently from this boxmunge root, every
operation that needs it fails with a message saying how to fix it.
"""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxmunge.docker_run import docker_env
from boxmunge.paths import BoxPaths
from boxmunge.userns.offset import RemapError, daemon_remapped

CONTAINER_NAME = "boxmunge-system"
# Where the container sees the operator's rclone config (system/compose.yml).
RCLONE_CONFIG = "/config/rclone/rclone.conf"
_DEFAULT_TIMEOUT = 600  # 10 minutes (backup dumps can be large)
_INSPECT_TIMEOUT = 10


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
        Mount(paths.rclone_config_dir.resolve(), "/config/rclone", directory=True),
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


def start_hint(paths: BoxPaths) -> str:
    """How an operator (re)starts the system container on this root."""
    return (
        f"Start it with: docker compose -f {paths.system_compose} up -d --build "
        "(install.sh does this on every install and upgrade). Backups, "
        "restores and backup-sync never fall back to host tools."
    )


def _inspect(name: str) -> dict[str, Any] | None:
    """Return `docker inspect` for the container, or None if it does not exist."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--type", "container", name],
            capture_output=True, text=True, check=False, timeout=_INSPECT_TIMEOUT,
            env=docker_env(),
        )
    except FileNotFoundError as e:
        raise SystemContainerError(f"docker CLI not found; cannot reach {name}.") from e
    except subprocess.TimeoutExpired as e:
        raise SystemContainerError(
            f"docker inspect {name} timed out after {_INSPECT_TIMEOUT}s; "
            "is the Docker daemon healthy?"
        ) from e
    if result.returncode != 0:
        if "No such container" in result.stderr:
            return None
        raise SystemContainerError(f"docker inspect {name} failed: {result.stderr.strip()}")
    return json.loads(result.stdout)[0]


def _check_mounts(info: dict[str, Any], paths: BoxPaths, name: str) -> None:
    actual = {m["Destination"]: Path(m["Source"]).resolve()
              for m in info.get("Mounts") or []}
    problems = [
        f"{m.container}: expected {m.host}, container has "
        f"{actual.get(m.container) or 'no mount'}"
        for m in system_mounts(paths) if actual.get(m.container) != m.host
    ]
    if problems:
        raise SystemContainerError(
            f"{name} is not mounted for the boxmunge root {paths.root}: "
            + "; ".join(problems)
            + f". Recreate it: docker compose -f {paths.system_compose} "
            "up -d --force-recreate"
        )


def platform_owner(paths: BoxPaths) -> tuple[int, int]:
    """uid and gid of the deploy user: the owner of the projects directory.

    The system container must run as exactly this user so that it can read
    the 0600 temp files boxmunge hands it and the group-readable backup key.
    """
    st = paths.projects.stat()
    return st.st_uid, st.st_gid


def _check_user(info: dict[str, Any], paths: BoxPaths, name: str) -> None:
    uid, gid = platform_owner(paths)
    expected = f"{uid}:{gid}"
    actual = info["Config"]["User"]
    if actual != expected:
        raise SystemContainerError(
            f"{name} runs as '{actual or 'the image default'}' but the deploy "
            f"user (owner of {paths.projects}) is {expected}, so age and rclone "
            "would hit 'permission denied'. Set BOXMUNGE_UID and BOXMUNGE_GID in "
            f"{paths.system / '.env'} (install.sh writes them) and recreate it: "
            f"docker compose -f {paths.system_compose} up -d --force-recreate"
        )


def _check_namespace(info: dict[str, Any], paths: BoxPaths, name: str) -> None:
    """Under a remapped daemon the container must be in the host user
    namespace. A container already there is right on any daemon, so the
    remap state is asked for only when it is not."""
    if info["HostConfig"]["UsernsMode"] == "host":
        return
    try:
        remapped = daemon_remapped(paths)
    except RemapError as e:
        raise SystemContainerError(
            f"{name} is not in the host user namespace, and boxmunge cannot tell "
            f"whether the Docker daemon is remapped: {e}") from e
    if remapped:
        raise SystemContainerError(
            f"{name} runs in the daemon's remapped user namespace, where it cannot read "
            f"{paths.backup_key} (root:deploy 0640) or write as deploy. Recreate it from "
            f"{paths.system_compose}, which sets userns_mode: host: docker compose -f "
            f"{paths.system_compose} up -d --force-recreate")


@dataclass(frozen=True)
class SystemTools:
    """A handle on a verified, running system container.

    Obtain one with ``connect``. Every path handed to a tool must go through
    ``path`` so it is translated onto the container's mounts (or rejected).
    """

    paths: BoxPaths
    name: str

    def path(self, host_path: Path) -> str:
        return container_path(host_path, self.paths)

    def run(self, cmd: list[str], timeout: int = _DEFAULT_TIMEOUT) -> subprocess.CompletedProcess[Any]:
        return system_exec(cmd, timeout=timeout, name=self.name)


def connect(paths: BoxPaths) -> SystemTools:
    """Verify the system container is running, as the deploy user, in a user
    namespace where that uid is deploy, with this root's mounts.

    Raises SystemContainerError, saying how to fix it, when the container is
    missing, not running, running as another uid, remapped on a remapped
    daemon, or mounted for a different boxmunge root.
    """
    name = CONTAINER_NAME
    info = _inspect(name)
    if info is None:
        raise SystemContainerError(f"The {name} container does not exist. {start_hint(paths)}")
    status = info["State"]["Status"]
    if status != "running":
        raise SystemContainerError(
            f"The {name} container is {status}, not running. {start_hint(paths)}"
        )
    _check_user(info, paths, name)
    _check_namespace(info, paths, name)
    _check_mounts(info, paths, name)
    return SystemTools(paths=paths, name=name)


def system_exec(
    cmd: list[str], timeout: int = _DEFAULT_TIMEOUT, name: str = CONTAINER_NAME,
) -> subprocess.CompletedProcess[Any]:
    """Execute a command inside the system container.

    Raises SystemContainerError on failure or timeout.
    """
    try:
        return subprocess.run(
            ["docker", "exec", name, *cmd],
            capture_output=True, text=True, check=True, timeout=timeout,
            env=docker_env(),
        )
    except subprocess.TimeoutExpired as e:
        raise SystemContainerError(f"Command timed out after {timeout}s: {' '.join(cmd)}") from e
    except subprocess.CalledProcessError as e:
        raise SystemContainerError(
            f"Command failed in system container: {' '.join(cmd)}\n{(e.stderr or '').strip()}"
        ) from e
