# SPDX-License-Identifier: Apache-2.0
"""Thin wrapper around Docker and Docker Compose CLI operations.

All Docker interaction goes through subprocess calls. This keeps boxmunge
simple and avoids the Docker SDK dependency.
"""

import fcntl
import logging
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from boxmunge.caddy_journal import JournalError, commit_sites, restore_sites
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.fileutil import open_shared_lockfile
from boxmunge.paths import (
    RESERVED_PROJECT_NAMES,
    STAGING_SUFFIX,
    validate_project_name,
)

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


class CaddyConfigRejected(DockerError):
    """Caddy rejected the config; the journaled site files were put back.

    `restored` names the site files restored to what Caddy last accepted;
    `refused` is why any journal entries were refused (caddy_journal), or "".
    """

    def __init__(self, message: str, restored: list[str], refused: str) -> None:
        super().__init__(message)
        self.restored = restored
        self.refused = refused


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
    force_recreate: bool = False,
    start: bool = True,
    services: list[str] | None = None,
) -> None:
    """Run docker compose up -d; force_recreate replaces unchanged containers
    too, and `services` limits it to those services.

    ``start=False`` (``--no-start``) builds and creates the project's
    networks, volumes and containers without starting any of them.

    Call it through boxmunge.compose_guard, which checks the project first.
    """
    cmd = compose_command(project_name, compose_files)
    cmd.extend(["up", "-d", "--remove-orphans"])
    if not start:
        cmd.append("--no-start")
    if build:
        cmd.append("--build")
    if force_recreate:
        cmd.append("--force-recreate")
    cmd.extend(services or [])
    _run(cmd, cwd=project_dir, timeout=_COMPOSE_UP_TIMEOUT)


def compose_down(
    project_dir: Path,
    compose_files: list[str] | None = None,
    *,
    project_name: str,
    remove_orphans: bool = False,
) -> None:
    """Run docker compose down in the project directory (`remove_orphans`:
    also containers of services the files no longer define)."""
    cmd = compose_command(project_name, compose_files)
    cmd.append("down")
    if remove_orphans:
        cmd.append("--remove-orphans")
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


def start_containers(names: list[str]) -> None:
    """Run docker start on existing containers (they mount what they were
    created with). Call it through boxmunge.compose_guard."""
    _run(["docker", "start", *names], capture=True)


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
    all_profiles: bool = False,
    project_directory: Path | None = None,
    env_file: Path | None = None,
) -> str:
    """Return `docker compose config --format json` output.

    The fully resolved model Compose will run: variables interpolated from
    the project's `.env` and the environment, `extends`/`include` merged,
    and paths made absolute. Client-side only; needs no daemon.

    Service env files are not read (``--no-env-resolution``): validation runs
    on bundles where on-box files such as secrets.env are absent, and never
    needs their values. Their paths still appear in the model, so env_file
    confinement is still checked.

    The model holds the services `up` starts: a service behind a profile
    that is not active is left out. ``all_profiles`` includes those too;
    validation and overlay generation pass it, because a profiled service
    still starts when something names it (restore runs
    `up <backup.service>`), so it must be validated and hardened too.

    ``project_directory`` and ``env_file`` resolve compose files kept
    elsewhere (production's release during a stage) as if they were in the
    project directory, interpolated from that release's own ``.env``.
    """
    cmd = compose_command(project_name, compose_files)
    if project_directory is not None:
        cmd.extend(["--project-directory", str(project_directory)])
    if env_file is not None:
        cmd.extend(["--env-file", str(env_file)])
    if all_profiles:
        cmd.extend(["--profile", "*"])
    cmd.extend(["config", "--format", "json", "--no-env-resolution"])
    result = _run(cmd, cwd=project_dir, capture=True)
    return result.stdout


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
            refused = ""
            try:
                restored = restore_sites(caddy_compose_dir)
            except JournalError as e:
                restored, refused = e.restored, str(e)
            raise CaddyConfigRejected(
                "Caddy config validation failed — reload aborted to prevent "
                "downtime. Restored the last accepted site config for: "
                f"{', '.join(restored) or '(none journaled)'}."
                + (f" Refused to restore from:\n{refused}" if refused else ""),
                restored, refused,
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
    services: list[str],
) -> None:
    """Pull the images of the named services (deployed_inventory.
    pulled_services): only those, because a service whose image only exists
    on this box (a build, or another service running it by its
    boxmunge.invalid/ name) fails the whole pull.
    ``--ignore-buildable`` stays as a second guard for build services.
    """
    if not services:
        raise ValueError("compose_pull needs at least one service to pull")
    cmd = compose_command(project_name, compose_files)
    cmd.extend(["pull", "--ignore-buildable", *services])
    _run(cmd, cwd=project_dir, timeout=_COMPOSE_UP_TIMEOUT)


def tag_image(source: str, target: str) -> None:
    """Run docker tag <source> <target>.

    Source is an image ID or a full reference (repo:tag, repo@sha256:...).
    A bare registry digest is not one: Docker looks a bare "sha256:..." up
    as an image ID, and a manifest digest is a different value.
    """
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


# The labels Compose puts on every container and image it makes.
COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
COMPOSE_SERVICE_LABEL = "com.docker.compose.service"


def compose_project_filter(project_name: str) -> list[str]:
    """Return `--filter label=com.docker.compose.project=<project>` for a
    validated compose project name.

    Every compose command runs with `-p <project>` (compose_command), so this
    label selects exactly that project's containers. Use it for every raw
    `docker` call that addresses a project's containers by label.
    """
    check_compose_project_name(project_name)
    return ["--filter", f"label={COMPOSE_PROJECT_LABEL}={project_name}"]


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
