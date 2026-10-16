"""Staging data snapshot — copy production data for staging use."""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Any

import yaml

from boxmunge.compose import managed_volume_keys
from boxmunge.compose_mounts import is_bind_entry, volume_source
from boxmunge.docker import compose_stop, compose_start
from boxmunge.docker_run import docker_env


class StagingDataError(Exception):
    """Raised when production data cannot be copied for staging."""


def parse_volumes(
    compose: dict[str, Any],
) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse a compose dict and return (bind_mounts, named_volumes).

    bind_mounts: list of (source_path, staging_path) tuples
    named_volumes: list of volume names
    Anonymous volumes have no name to copy between projects and are skipped.
    """
    bind_mounts: dict[str, str] = {}
    named_volumes: set[str] = set()

    for svc in (compose.get("services") or {}).values():
        for vol in svc.get("volumes") or []:
            if is_bind_entry(vol):
                source = volume_source(vol)
                bind_mounts.setdefault(source, source + "-staging")
            elif isinstance(vol, str) and ":" in vol:
                named_volumes.add(vol.split(":", 1)[0])
            elif isinstance(vol, dict) and vol.get("source"):
                named_volumes.add(vol["source"])

    return list(bind_mounts.items()), sorted(named_volumes)


def _run_in_system_container(cmd: str) -> None:
    """Execute a command inside the boxmunge-system container."""
    subprocess.run(
        ["docker", "exec", "boxmunge-system", "sh", "-c", cmd],
        check=True, capture_output=True, text=True,
        timeout=300,
        env=docker_env(),
    )


def _docker_run(cmd: list[str]) -> None:
    """Run a short-lived Docker container."""
    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300, env=docker_env())


def copy_bind_mounts(
    bind_mounts: list[tuple[str, str]], project_name: str,
) -> None:
    """Copy bind-mount directories via the system container.

    The system container has /projects mounted, so relative paths like
    ./data are resolved as /projects/{project}/data. Absolute paths
    within the project tree are mapped to /projects/{project}/... as well.
    """
    project_prefix = f"/opt/boxmunge/projects/{project_name}/"
    for source, dest in bind_mounts:
        if source.startswith("./") or source.startswith("../"):
            src_rel = source.removeprefix("./")
            dst_rel = dest.removeprefix("./")
            src_path = f"/projects/{project_name}/{src_rel}"
            dst_path = f"/projects/{project_name}/{dst_rel}"
        elif source.startswith(project_prefix):
            src_path = "/projects/" + source.removeprefix("/opt/boxmunge/projects/")
            dst_path = "/projects/" + dest.removeprefix("/opt/boxmunge/projects/")
        else:
            raise ValueError(
                f"Cannot copy bind mount '{source}': absolute path outside "
                f"project tree. Copy manually or use a relative path."
            )
        _run_in_system_container(
            f"rm -rf {shlex.quote(dst_path)} && "
            f"cp -a {shlex.quote(src_path)} {shlex.quote(dst_path)}"
        )


def copy_named_volumes(
    named_volumes: list[str], project_name: str,
) -> None:
    """Copy named volumes via short-lived busybox containers.

    Docker Compose names volumes as {project}_{volume}. The staging
    project name is {project}-staging, so staging volumes are
    {project}-staging_{volume}.
    """
    for vol in named_volumes:
        prod_vol = f"{project_name}_{vol}"
        staging_vol = f"{project_name}-staging_{vol}"
        _docker_run([
            "docker", "run", "--rm",
            "-v", f"{prod_vol}:/src:ro",
            "-v", f"{staging_vol}:/dst",
            "busybox", "sh", "-c",
            "rm -rf /dst/* && cp -a /src/. /dst/",
        ])


def snapshot_prod_data(
    project_name: str,
    project_dir: Path,
    manifest: dict[str, Any],
) -> None:
    """Snapshot production data for staging use.

    The data is every bind mount and named volume in compose.yml plus the
    named volumes the manifest declares (``writable.persistent``), which
    only the generated overlay mounts. Stops production, copies them all,
    then restarts production. If copying fails, production is still
    restarted before the exception propagates. Raises StagingDataError when
    there is nothing to copy: copy_data was asked for, so that is a
    misconfiguration, not a successful copy.
    """
    compose = yaml.safe_load((project_dir / "compose.yml").read_text())
    bind_mounts, named_volumes = parse_volumes(compose)
    named_volumes = sorted(set(named_volumes) | set(managed_volume_keys(manifest)))

    if not bind_mounts and not named_volumes:
        raise StagingDataError(
            "staging.copy_data is set, but the project declares no data to "
            "copy: no volumes in compose.yml and no writable.persistent "
            "entries in the manifest."
        )

    prod_compose_files = ["compose.yml", "compose.boxmunge.yml"]
    compose_stop(project_dir, compose_files=prod_compose_files,
                 project_name=project_name, timeout=15)
    try:
        if bind_mounts:
            copy_bind_mounts(bind_mounts, project_name)
        if named_volumes:
            copy_named_volumes(named_volumes, project_name)
    finally:
        compose_start(project_dir, compose_files=prod_compose_files,
                      project_name=project_name)
