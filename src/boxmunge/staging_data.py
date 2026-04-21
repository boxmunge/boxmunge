"""Staging data snapshot — copy production data for staging use."""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Any

import yaml

from boxmunge.compose import is_bind_mount
from boxmunge.docker import compose_stop, compose_start


def parse_volumes(
    compose: dict[str, Any],
) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse a compose dict and return (bind_mounts, named_volumes).

    bind_mounts: list of (source_path, staging_path) tuples
    named_volumes: list of volume names
    """
    bind_mounts: dict[str, str] = {}
    named_volumes: set[str] = set()

    for svc in (compose.get("services") or {}).values():
        for vol in svc.get("volumes", []):
            parts = vol.split(":")
            host_part = parts[0]
            if is_bind_mount(vol):
                if host_part not in bind_mounts:
                    bind_mounts[host_part] = host_part + "-staging"
            else:
                named_volumes.add(host_part)

    return list(bind_mounts.items()), sorted(named_volumes)


def _run_in_system_container(cmd: str) -> None:
    """Execute a command inside the boxmunge-system container."""
    subprocess.run(
        ["docker", "exec", "boxmunge-system", "sh", "-c", cmd],
        check=True, capture_output=True, text=True,
        timeout=300,
    )


def _docker_run(cmd: list[str]) -> None:
    """Run a short-lived Docker container."""
    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)


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
    compose_path: Path | str,
) -> None:
    """Snapshot production data for staging use.

    Stops production, copies all bind mounts and named volumes,
    then restarts production. If copying fails, production is
    still restarted before the exception propagates.
    """
    raw = Path(compose_path).read_text()
    compose = yaml.safe_load(raw)
    bind_mounts, named_volumes = parse_volumes(compose)

    if not bind_mounts and not named_volumes:
        return

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
