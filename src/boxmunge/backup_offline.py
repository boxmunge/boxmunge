# SPDX-License-Identifier: Apache-2.0
"""Run a backup dump over a stopped service's data, offline.

A dump normally runs in the backup service's running container (`compose
exec`, service_exec). When the service is stopped (the project is
quarantined, paused or stopped by the health monitor, or `data chown`
stopped it), its data is at rest, and a dump that only reads files (a
SQLite `.dump`, a tar of a data directory) can read it from a one-off
container of the service: `compose run --rm --no-deps`, with the
production files and a scratch overlay that takes the container off every
network (`network_mode: none`) and publishes nothing. It runs the
service's own image as its own user over its own mounts, through the start
checks (compose_guard.check_start), and starts nothing else; its entrypoint
is `sh`, so the service itself never starts. A dump that needs the
service running (pg_dump connects to its server) fails, and says so.

On a timeout or an interruption the one-off is force-removed by its name.
"""
from __future__ import annotations

import json
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from boxmunge.backup import BackupError
from boxmunge.compose_guard import check_start
from boxmunge.compose_resolve import ComposeResolveError, resolve_deployed_config
from boxmunge.docker import compose_command
from boxmunge.docker_containers import absent_images
from boxmunge.docker_run import DockerError, docker_env, run as _run
from boxmunge.paths import BoxPaths

PROD_FILES = ["compose.yml", "compose.boxmunge.yml"]
_RM_TIMEOUT = 60


def _scratch_overlay(service: str) -> str:
    # `!reset` (Compose 2.24+; boxmunge needs 2.35) drops the service's
    # networks and ports; network_mode cannot be combined with networks.
    name = json.dumps(service)
    return (f"services:\n  {name}:\n    network_mode: none\n"
            f"    networks: !reset null\n    ports: !reset []\n")


def _image(paths: BoxPaths, project: str, service: str) -> str:
    try:
        model = resolve_deployed_config(paths.project_dir(project), PROD_FILES, project,
                                        all_profiles=True)
    except ComposeResolveError as e:
        raise BackupError(f"cannot resolve {project}'s compose files: {e}") from e
    spec = (model.get("services") or {}).get(service)
    image = spec.get("image") if isinstance(spec, dict) else None
    if not isinstance(image, str):
        raise BackupError(f"{project} has no service {service} with an image to dump from")
    return image


def _remove(name: str) -> str | None:
    """Force-remove the one-off; why it may still exist, or None."""
    try:
        _run(["docker", "rm", "-f", name], capture=True, timeout=_RM_TIMEOUT)
    except DockerError as e:
        return str(e)
    return None


def run_offline(paths: BoxPaths, project: str, service: str, command: str, *,
                timeout: float, component: str, **run_kwargs: Any
                ) -> subprocess.CompletedProcess:
    """`sh -c command` in a one-off, offline container of `service`, bounded
    by `timeout`. Raises BackupError when it cannot run (the start checks
    refuse, its image is gone) or overruns."""
    try:
        check_start(paths, project, component=component, compose_files=PROD_FILES)
        missing = absent_images({service: _image(paths, project, service)})
    except DockerError as e:
        raise BackupError(f"the one-off dump container cannot start: {e}") from e
    if missing:
        raise BackupError(f"the image of {service} ({missing[0][1]}) is not in the local "
                          f"image store, so there is nothing to dump with; a deploy "
                          f"builds or pulls it")
    project_dir = paths.project_dir(project)
    name = f"{project}-{service}-dump-{secrets.token_hex(6)}"
    with tempfile.TemporaryDirectory(prefix="boxmunge-dump-") as scratch:
        overlay = Path(scratch) / "offline.yml"
        overlay.write_text(_scratch_overlay(service))
        cmd = [*compose_command(project, [*PROD_FILES, str(overlay)]),
               "run", "--rm", "--no-deps", "-T", "--pull", "never", "--name", name,
               "--entrypoint", "sh", service, "-c", command]
        try:
            return subprocess.run(cmd, cwd=project_dir, timeout=timeout, env=docker_env(),
                                  **run_kwargs)
        except subprocess.TimeoutExpired as e:
            left = _remove(name)
            raise BackupError(
                f"the dump timed out after {timeout}s; "
                + (f"its one-off container {name} was removed" if left is None else
                   f"removing its one-off container {name} FAILED ({left}): remove it "
                   f"with `docker rm -f {name}`")) from e
        except OSError:
            raise  # nothing started
        except BaseException:
            _remove(name)
            raise
