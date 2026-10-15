# SPDX-License-Identifier: Apache-2.0
"""Thin wrapper around Docker and Docker Compose CLI operations.

All Docker interaction goes through subprocess calls. This keeps boxmunge
simple and avoids the Docker SDK dependency.
"""

import fcntl
import logging
import os
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from boxmunge.caddy_journal import commit_sites, restore_sites
from boxmunge.fileutil import open_shared_lockfile
from boxmunge.paths import (
    RESERVED_PROJECT_NAMES,
    STAGING_SUFFIX,
    validate_project_name,
)

_DEFAULT_TIMEOUT = 120
_COMPOSE_UP_TIMEOUT = 300
_CADDY_RELOAD_TIMEOUT = 30
# Audit D-NEW-2: caddy_validate previously inherited the 120s default. Under
# the reload lock, that meant a crashed Caddy could block every other deploy
# for two minutes. 30s matches the reload timeout — long enough for a healthy
# Caddy, short enough that a wedged container doesn't hold the queue hostage.
_CADDY_VALIDATE_TIMEOUT = 30
# Audit E-NEW-3: log a warning when a deploy waits more than this long for
# the global Caddy reload lock — visible signal that deploys are queueing.
_CADDY_LOCK_WAIT_WARN_SECONDS = 0.1
# Fixed by caddy/compose.yml (`container_name`).
_CADDY_CONTAINER = "boxmunge-caddy"


class DockerError(Exception):
    """Raised when a Docker/Compose operation fails."""


class CaddyConfigRejected(DockerError):
    """Caddy rejected the config; the journaled site files were put back.

    `restored` names the site files restored to what Caddy last accepted.
    """

    def __init__(self, message: str, restored: list[str]) -> None:
        super().__init__(message)
        self.restored = restored


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


def check_compose_project_name(name: str) -> None:
    """Raise ValueError unless `name` is a project name, its staging name,
    or one of the platform's own stacks (RESERVED_PROJECT_NAMES).

    Every compose invocation names its project explicitly with `-p`, so a
    compose file's top-level `name:` or the directory name can never
    redirect a command at another project's containers.
    """
    if name in RESERVED_PROJECT_NAMES:
        return
    base = name
    if isinstance(name, str) and name.endswith(STAGING_SUFFIX):
        base = name[:-len(STAGING_SUFFIX)]
    validate_project_name(base)


def staging_compose_project(project: str) -> str:
    """Return the compose project name of a project's staging copy."""
    validate_project_name(project)
    return f"{project}{STAGING_SUFFIX}"


def compose_command(project_name: str, compose_files: list[str] | None) -> list[str]:
    """Return `docker compose -p <project> -f ...` for a validated project.

    Use this for every compose invocation, including ones run outside this
    module (exec, streaming logs), so none relies on Compose's own
    project-name inference.
    """
    check_compose_project_name(project_name)
    cmd = ["docker", "compose", "-p", project_name]
    for f in (compose_files or ["compose.yml"]):
        cmd.extend(["-f", f])
    return cmd


def compose_up(
    project_dir: Path,
    compose_files: list[str] | None = None,
    build: bool = True,
    *,
    project_name: str,
) -> None:
    """Run docker compose up -d in the project directory."""
    cmd = compose_command(project_name, compose_files)
    cmd.extend(["up", "-d", "--remove-orphans"])
    if build:
        cmd.append("--build")
    _run(cmd, cwd=project_dir, timeout=_COMPOSE_UP_TIMEOUT)


def compose_down(
    project_dir: Path,
    compose_files: list[str] | None = None,
    *,
    project_name: str,
) -> None:
    """Run docker compose down in the project directory."""
    cmd = compose_command(project_name, compose_files)
    cmd.append("down")
    _run(cmd, cwd=project_dir)


def compose_stop(
    project_dir: Path,
    compose_files: list[str] | None = None,
    *,
    project_name: str,
    timeout: int = 15,
) -> None:
    """Run docker compose stop (without removing containers or volumes)."""
    cmd = compose_command(project_name, compose_files)
    cmd.extend(["stop", "-t", str(timeout)])
    _run(cmd, cwd=project_dir)


def compose_start(
    project_dir: Path,
    compose_files: list[str] | None = None,
    *,
    project_name: str,
) -> None:
    """Run docker compose start (restart previously stopped containers)."""
    cmd = compose_command(project_name, compose_files)
    cmd.append("start")
    _run(cmd, cwd=project_dir)


def compose_logs(
    project_dir: Path,
    service: str | None = None,
    tail: int = 100,
    follow: bool = False,
    compose_files: list[str] | None = None,
    *,
    project_name: str,
) -> None:
    """Show docker compose logs."""
    cmd = compose_command(project_name, compose_files)
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
    *,
    project_name: str,
) -> str:
    """Capture docker compose logs as a string."""
    cmd = compose_command(project_name, compose_files)
    cmd.extend(["logs", f"--tail={tail}", "--no-color"])
    if service:
        cmd.append(service)
    result = _run(cmd, cwd=project_dir, capture=True)
    return result.stdout


def compose_ps(
    project_dir: Path,
    compose_files: list[str] | None = None,
    *,
    project_name: str,
) -> str:
    """Get docker compose ps output."""
    cmd = compose_command(project_name, compose_files)
    cmd.extend(["ps", "--format", "json"])
    result = _run(cmd, cwd=project_dir, capture=True)
    return result.stdout


def compose_config(
    project_dir: Path,
    compose_files: list[str] | None = None,
    *,
    project_name: str,
) -> str:
    """Return `docker compose config --format json` output.

    The fully resolved model Compose will run: variables interpolated from
    the project's `.env` and the environment, `extends`/`include` merged,
    and paths made absolute. Client-side only; needs no daemon.

    Service env files are not read (``--no-env-resolution``): validation runs
    on bundles where on-box files such as secrets.env are absent, and never
    needs their values. Their paths still appear in the model, so env_file
    confinement is still checked.
    """
    cmd = compose_command(project_name, compose_files)
    cmd.extend(["config", "--format", "json", "--no-env-resolution"])
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


@contextmanager
def caddy_config_lock(lock_dir: Path) -> Iterator[None]:
    """Global Caddy config flock. Blocking, bounded section.

    Serialises validate+reload across concurrent deploys so deploy-A cannot
    pass validate, then have deploy-B write a malformed site config that
    deploy-A's subsequent reload ingests and fails on. Site writers that
    journal their previous content (`caddy.prepare_caddy_config`) take it
    too, so a restore never races a write. The protected section is short
    (~100ms typical), so blocking is fine. Not re-entrant: never nest it.

    Audit E-NEW-3: any wait longer than the warn threshold is logged via
    the boxmunge logger so prolonged contention is visible in operations.
    Happy-path waits stay silent.
    """
    lock_path = lock_dir / ".caddy.lock"
    fd = open_shared_lockfile(lock_path)
    try:
        start = time.monotonic()
        fcntl.flock(fd, fcntl.LOCK_EX)
        elapsed = time.monotonic() - start
        if elapsed >= _CADDY_LOCK_WAIT_WARN_SECONDS:
            logging.getLogger("boxmunge").warning(
                "caddy reload waited %.1fs for lock", elapsed,
            )
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def caddy_reload(caddy_compose_dir: Path, lock_dir: Path) -> None:
    """Reload Caddy configuration gracefully under a global lock.

    Validates first to prevent bad config; the (validate + reload) sequence
    runs under a flock at lock_dir/.caddy.lock so two concurrent deploys
    cannot race past each other's validate. Callers pass paths.state as
    lock_dir.

    When Caddy rejects the config, every site file written since Caddy
    last accepted one (see `caddy_journal`) is put back, so the bad file
    does not break the next reload or a Caddy restart, and
    CaddyConfigRejected is raised: callers must fail the operation. When
    Caddy is not running nothing can be validated, the new files stay in
    place, and a plain DockerError is raised.
    """
    with caddy_config_lock(lock_dir):
        if not caddy_validate(caddy_compose_dir):
            if not container_running(_CADDY_CONTAINER):
                raise DockerError(
                    "Caddy is not running, so the new site config could not "
                    "be validated or loaded. Start Caddy and run `doctor`."
                )
            restored = restore_sites(caddy_compose_dir)
            raise CaddyConfigRejected(
                "Caddy config validation failed — reload aborted to prevent "
                "downtime. Restored the last accepted site config for: "
                f"{', '.join(restored) or '(none journaled)'}.",
                restored,
            )
        commit_sites(caddy_compose_dir)
        _run(
            ["docker", "compose", "exec", "caddy", "caddy", "reload",
             "--config", "/etc/caddy/Caddyfile"],
            cwd=caddy_compose_dir,
            timeout=_CADDY_RELOAD_TIMEOUT,
        )


def caddy_validate(caddy_compose_dir: Path) -> bool:
    """Validate Caddy configuration. Returns True if valid.

    Audit D-NEW-2: capped at _CADDY_VALIDATE_TIMEOUT (30s) so a wedged
    Caddy container can't hold the reload lock for the full 120s default.
    """
    try:
        _run(
            ["docker", "compose", "exec", "caddy", "caddy", "validate",
             "--config", "/etc/caddy/Caddyfile"],
            cwd=caddy_compose_dir,
            capture=True,
            timeout=_CADDY_VALIDATE_TIMEOUT,
        )
        return True
    except DockerError:
        return False


def compose_pull(
    project_dir: Path,
    compose_files: list[str] | None = None,
    *,
    project_name: str,
) -> None:
    """Run docker compose pull in the project directory.

    Pulls latest images for all services with image: directives.
    Build: services are unaffected.
    """
    cmd = compose_command(project_name, compose_files)
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


def compose_project_filter(project_name: str) -> list[str]:
    """Return `--filter label=com.docker.compose.project=<project>` for a
    validated compose project name.

    Every compose command runs with `-p <project>` (compose_command), so this
    label selects exactly that project's containers. Use it for every raw
    `docker` call that addresses a project's containers by label.
    """
    check_compose_project_name(project_name)
    return ["--filter", f"label=com.docker.compose.project={project_name}"]


def project_restart_policies(*, project_name: str) -> dict[str, str]:
    """Map each container of a compose project to its restart policy.

    Policies use `docker update --restart` syntax: "no", "always",
    "unless-stopped", "on-failure" or "on-failure:<max retries>".
    """
    listed = _run(
        ["docker", "ps", "-a", *compose_project_filter(project_name),
         "--format", "{{.Names}}"],
        capture=True,
    )
    names = sorted(n for n in listed.stdout.split() if n)
    if not names:
        return {}
    inspected = _run(
        ["docker", "inspect", "--format",
         "{{.Name}}|{{.HostConfig.RestartPolicy.Name}}|"
         "{{.HostConfig.RestartPolicy.MaximumRetryCount}}", *names],
        capture=True,
    )
    policies: dict[str, str] = {}
    for line in inspected.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.strip().split("|")
        if len(parts) != 3:
            raise DockerError(f"unexpected docker inspect output: {line!r}")
        name, policy, retries = parts[0].lstrip("/"), parts[1] or "no", parts[2]
        if policy == "on-failure" and retries not in ("", "0"):
            policy = f"on-failure:{retries}"
        policies[name] = policy
    return policies


def set_restart_policy(container_names: list[str], policy: str) -> None:
    """Run docker update --restart=<policy> on the named containers."""
    if container_names:
        _run(["docker", "update", f"--restart={policy}", *container_names])


def container_image_id(container_name: str) -> str | None:
    """The local image ID ("sha256:...") a container was created from.

    Unlike container_image_digest this needs no registry digest, so it
    identifies locally built images too. None if there is no such container.
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
    return image_id if image_id.startswith("sha256:") else None


def local_image_id(image_ref: str) -> str | None:
    """The local image ID for an image name, or None if it is not present."""
    try:
        result = _run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
            capture=True,
            check=False,
        )
    except DockerError:
        return None
    image_id = result.stdout.strip()
    return image_id if image_id.startswith("sha256:") else None
