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
