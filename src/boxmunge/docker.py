# SPDX-License-Identifier: Apache-2.0
"""Thin wrapper around Docker and Docker Compose CLI operations.

All Docker interaction goes through subprocess calls. This keeps boxmunge
simple and avoids the Docker SDK dependency.
"""

import subprocess
from pathlib import Path
from typing import Any

_DEFAULT_TIMEOUT = 120
_COMPOSE_UP_TIMEOUT = 300
_CADDY_RELOAD_TIMEOUT = 30


class DockerError(Exception):
    """Raised when a Docker/Compose operation fails."""


def _run(
    cmd: list[str],
    cwd: Path | None = None,
    capture: bool = False,
    check: bool = True,
    timeout: int = _DEFAULT_TIMEOUT,
) -> subprocess.CompletedProcess:
    """Run a command, optionally capturing output. Raises DockerError on failure."""
    try:
        return subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=capture,
            text=True,
            check=check,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise DockerError(
            f"Command timed out after {timeout}s: {' '.join(cmd)}"
        ) from e
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""
        raise DockerError(
            f"Command failed: {' '.join(cmd)}\n{stderr.strip()}"
        ) from e


def compose_up(
    project_dir: Path,
    compose_files: list[str] | None = None,
    build: bool = True,
    project_name: str | None = None,
) -> None:
    """Run docker compose up -d in the project directory."""
    cmd = ["docker", "compose"]
    if project_name:
        cmd.extend(["-p", project_name])
    for f in (compose_files or ["compose.yml"]):
        cmd.extend(["-f", f])
    cmd.extend(["up", "-d", "--remove-orphans"])
    if build:
        cmd.append("--build")
    _run(cmd, cwd=project_dir, timeout=_COMPOSE_UP_TIMEOUT)


def compose_down(
    project_dir: Path,
    compose_files: list[str] | None = None,
    project_name: str | None = None,
) -> None:
    """Run docker compose down in the project directory."""
    cmd = ["docker", "compose"]
    if project_name:
        cmd.extend(["-p", project_name])
    for f in (compose_files or ["compose.yml"]):
        cmd.extend(["-f", f])
    cmd.append("down")
    _run(cmd, cwd=project_dir)


def compose_stop(
    project_dir: Path,
    compose_files: list[str] | None = None,
    project_name: str | None = None,
    timeout: int = 15,
) -> None:
    """Run docker compose stop (without removing containers or volumes)."""
    cmd = ["docker", "compose"]
    if project_name:
        cmd.extend(["-p", project_name])
    for f in (compose_files or ["compose.yml"]):
        cmd.extend(["-f", f])
    cmd.extend(["stop", "-t", str(timeout)])
    _run(cmd, cwd=project_dir)


def compose_start(
    project_dir: Path,
    compose_files: list[str] | None = None,
    project_name: str | None = None,
) -> None:
    """Run docker compose start (restart previously stopped containers)."""
    cmd = ["docker", "compose"]
    if project_name:
        cmd.extend(["-p", project_name])
    for f in (compose_files or ["compose.yml"]):
        cmd.extend(["-f", f])
    cmd.append("start")
    _run(cmd, cwd=project_dir)


def compose_logs(
    project_dir: Path,
    service: str | None = None,
    tail: int = 100,
    follow: bool = False,
    compose_files: list[str] | None = None,
) -> None:
    """Show docker compose logs."""
    cmd = ["docker", "compose"]
    for f in (compose_files or ["compose.yml"]):
        cmd.extend(["-f", f])
    cmd.extend(["logs", f"--tail={tail}"])
    if follow:
        cmd.append("--follow")
    if service:
        cmd.append(service)
    _run(cmd, cwd=project_dir)


def compose_logs_capture(
    project_dir: Path,
    service: str | None = None,
    tail: int = 100,
    compose_files: list[str] | None = None,
) -> str:
    """Capture docker compose logs as a string."""
    cmd = ["docker", "compose"]
    for f in (compose_files or ["compose.yml"]):
        cmd.extend(["-f", f])
    cmd.extend(["logs", f"--tail={tail}", "--no-color"])
    if service:
        cmd.append(service)
    result = _run(cmd, cwd=project_dir, capture=True)
    return result.stdout


def compose_ps(
    project_dir: Path,
    compose_files: list[str] | None = None,
) -> str:
    """Get docker compose ps output."""
    cmd = ["docker", "compose"]
    for f in (compose_files or ["compose.yml"]):
        cmd.extend(["-f", f])
    cmd.extend(["ps", "--format", "json"])
    result = _run(cmd, cwd=project_dir, capture=True)
    return result.stdout


def container_health(container_name: str) -> str | None:
    """Get the health status of a container. Returns None if no healthcheck."""
    result = _run(
        ["docker", "inspect", "--format", "{{.State.Health.Status}}", container_name],
        capture=True,
        check=False,
    )
    status = result.stdout.strip()
    if not status or status == "<no value>":
        return None
    return status


def caddy_reload(caddy_compose_dir: Path) -> None:
    """Reload Caddy configuration gracefully. Validates first to prevent bad config."""
    if not caddy_validate(caddy_compose_dir):
        raise DockerError("Caddy config validation failed — reload aborted to prevent downtime")
    _run(
        ["docker", "compose", "exec", "caddy", "caddy", "reload",
         "--config", "/etc/caddy/Caddyfile"],
        cwd=caddy_compose_dir,
        timeout=_CADDY_RELOAD_TIMEOUT,
    )


def caddy_validate(caddy_compose_dir: Path) -> bool:
    """Validate Caddy configuration. Returns True if valid."""
    try:
        _run(
            ["docker", "compose", "exec", "caddy", "caddy", "validate",
             "--config", "/etc/caddy/Caddyfile"],
            cwd=caddy_compose_dir,
            capture=True,
        )
        return True
    except DockerError:
        return False


def compose_pull(
    project_dir: Path,
    compose_files: list[str] | None = None,
    project_name: str | None = None,
) -> None:
    """Run docker compose pull in the project directory.

    Pulls latest images for all services with image: directives.
    Build: services are unaffected.
    """
    cmd = ["docker", "compose"]
    if project_name:
        cmd.extend(["-p", project_name])
    for f in (compose_files or ["compose.yml"]):
        cmd.extend(["-f", f])
    cmd.append("pull")
    _run(cmd, cwd=project_dir, timeout=_COMPOSE_UP_TIMEOUT)


def image_digest(image_ref: str) -> str | None:
    """Return the local image digest for an image reference, or None.

    Uses docker inspect on the image (not the container). Returns the
    first RepoDigest if present.
    """
    try:
        result = _run(
            ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", image_ref],
            capture=True,
        )
    except DockerError:
        return None
    raw = result.stdout.strip()
    if not raw or raw == "<no value>":
        return None
    if "@" in raw:
        return raw.split("@", 1)[1]
    return raw if raw.startswith("sha256:") else None


def container_image_digest(container_name: str) -> str | None:
    """Return the image digest the named container is currently running.

    Returns None if the container doesn't exist or has no resolvable digest.
    """
    try:
        result = _run(
            ["docker", "inspect", "--format", "{{.Image}}", container_name],
            capture=True,
            check=False,
        )
    except DockerError:
        return None
    image_id = result.stdout.strip()
    if not image_id or image_id == "<no value>":
        return None
    return image_digest(image_id)


def tag_image(source: str, target: str) -> None:
    """Run docker tag <source> <target>. Source can be a digest or tag."""
    _run(["docker", "tag", source, target])


def container_running(container_name: str) -> bool:
    """Return True if the container exists and is in 'running' state."""
    try:
        result = _run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
            capture=True,
            check=False,
        )
    except DockerError:
        return False
    return result.stdout.strip() == "true"
