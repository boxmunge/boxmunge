# SPDX-License-Identifier: Apache-2.0
"""Copy production's data into staging's stores (``staging.copy_data``).

The copy runs only while both sides are quiescent: production's running
containers are stopped for it and started again afterwards, whatever
happens, and staging must have no running container (its containers exist,
created but not started, so Compose has made its volumes). Every source
must exist: Docker would otherwise create an empty volume and the copy
would "succeed" with no data. Each destination is emptied completely,
hidden entries included, before the source is copied in.
"""
from __future__ import annotations

import os
import shlex
import sys
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boxmunge import docker_containers
from boxmunge.docker import staging_compose_project
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.release import project_data_dirs
from boxmunge.staging_copy_plan import (
    CopyPlan, StagingDataError, Store, copy_sources, plan_copy, stores,
)

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

__all__ = ["ProductionDownError", "StagingDataError", "copy_production_data",
           "plan_staging_copy", "prepare_destinations", "run_throwaway"]

COPY_IMAGE = "busybox:1.36"
_COPY_TIMEOUT = 1800
_STOP_TIMEOUT = 15
# Empty /dst, hidden entries included, and prove it is empty.
_EMPTY_DST = 'rm -rf /dst/* /dst/.[!.]* /dst/..?* && [ -z "$(ls -A /dst)" ]'


def plan_staging_copy(paths: BoxPaths, project: str, manifest: dict[str, Any],
                      prod_model: dict[str, Any], staging_model: dict[str, Any]) -> CopyPlan:
    """Plan the copy from the two environments' resolved models."""
    project_dir = paths.project_dir(project)
    data = project_data_dirs(project_dir).box_state()
    plan = plan_copy(
        stores(prod_model, project, project_dir, data, staging=False),
        stores(staging_model, staging_compose_project(project), project_dir, data,
               staging=True),
        copy_sources(manifest) or {}, project)
    if not plan.pairs:
        raise StagingDataError(
            "staging.copy_data is set, but none of production's data is copied: "
            "no volume or data directory of production's matches one the staged "
            "release mounts. Remove copy_data, or map the stores with "
            "staging.copy_data.sources.")
    return plan


def _volume_exists(name: str) -> bool:
    try:
        _run(["docker", "volume", "inspect", name], capture=True)
    except DockerError as e:
        if "no such volume" in str(e).lower():
            return False
        raise
    return True


def _is_file(store: Store, side: str) -> bool:
    """Whether the store is a file; raises if a source (or a staging
    volume, which Compose created) is missing."""
    if store.kind == "volume":
        if not _volume_exists(store.ref):
            raise StagingDataError(
                f"{side} volume {store.ref} ({store.key}) does not exist. Nothing "
                f"was copied: copying from it would create an empty volume.")
        return False
    if not os.path.lexists(store.ref):
        if side == "staging":
            return False  # the copy creates it
        raise StagingDataError(
            f"production's {store.key} ({store.ref}) does not exist, so there is "
            f"nothing to copy from it. Nothing was copied.")
    if os.path.islink(store.ref):
        raise StagingDataError(f"{store.ref} is a symlink; refusing to copy through it")
    return os.path.isfile(store.ref)


def verify_plan(plan: CopyPlan) -> list[bool]:
    """Every source exists, and each pair copies a file to a file or a
    directory to a directory. Returns, per pair, whether it is a file."""
    kinds = []
    for src, dest in plan.pairs:
        src_file = _is_file(src, "production")
        dest_file = _is_file(dest, "staging") if (
            dest.kind == "volume" or os.path.lexists(dest.ref)) else src_file
        if src_file != dest_file:
            raise StagingDataError(
                f"cannot copy {src.label} to staging's {dest.label}: one is a "
                f"file and the other a directory.")
        kinds.append(src_file)
    return kinds


def _mount(store: Store, at: str, ro: bool) -> list[str]:
    return ["--mount", f"type={store.kind},src={store.ref},dst={at}" + (",readonly" if ro else "")]


def run_throwaway(project: str, mounts: list[str], script: str) -> None:
    """Run ``script`` in a named, networkless busybox container.

    `docker run --rm` alone outlives an interrupted boxmunge (the CLI's
    signals go to the container's PID 1, which ignores them), so the
    container is named and always force-removed afterwards.
    """
    name = f"boxmunge-{staging_compose_project(project)}-copy-{uuid.uuid4().hex[:8]}"
    try:
        _run(["docker", "run", "--rm", "--name", name, "--network", "none", *mounts,
              COPY_IMAGE, "sh", "-c", script], capture=True, timeout=_COPY_TIMEOUT)
    finally:
        try:
            _run(["docker", "rm", "-f", name], capture=True)
        except DockerError as e:
            if "no such container" not in str(e).lower():
                raise


def _copy(project: str, src: Store, dest: Store, is_file: bool) -> None:
    source = _mount(src, "/src", True)
    if is_file:
        # Mount the destination's directory; the file is replaced whole.
        name = shlex.quote(Path(dest.ref).name)
        run_throwaway(project, [*source, "-v", f"{Path(dest.ref).parent}:/dst"],
                      f"rm -rf /dst/{name} && cp -a /src /dst/{name}")
        return
    # A staging volume exists (verified); -v creates a missing directory.
    dst = _mount(dest, "/dst", False) if dest.kind == "volume" else ["-v", f"{dest.ref}:/dst"]
    run_throwaway(project, [*source, *dst], f"{_EMPTY_DST} && cp -a /src/. /dst/")


def prepare_destinations(project: str, project_dir: Path, plan: CopyPlan) -> None:
    """Make each bind destination exist before Compose creates staging's
    containers, which refuses a missing config or secret file. The copy
    replaces these placeholders; they are made as root, like the copy."""
    for src, dest in plan.pairs:
        if dest.kind != "bind" or os.path.lexists(dest.ref):
            continue
        is_file = _is_file(src, "production")
        top, _, rest = os.path.relpath(dest.ref, project_dir).partition(os.sep)
        parent, name = os.path.split(rest)
        script = (f"mkdir -p /x/{shlex.quote(parent)} && touch /x/{shlex.quote(rest)}"
                  if is_file and name else f"mkdir -p /x/{shlex.quote(rest)}")
        run_throwaway(project, ["-v", f"{project_dir / top}:/x"], script)


def _running(compose_project: str) -> list[str]:
    return [c.name for c in docker_containers.project_containers(compose_project)
            if c.running]


class ProductionDownError(DockerError):
    """Production was stopped for the copy and could not be started again."""


def _start_again(stopped: list[str], cause: BaseException | None) -> None:
    try:
        _run(["docker", "start", *stopped], capture=True)
    except DockerError as e:
        names = " ".join(stopped)
        message = (f"PRODUCTION IS DOWN: its containers were stopped for the data "
                   f"copy and starting them again failed: {e}. Start them with: "
                   f"docker start {names}")
        print(f"ERROR: {message}", file=sys.stderr)
        raise ProductionDownError(message) from (cause or e)
    print("  Production started again.")


def copy_production_data(project: str, plan: CopyPlan) -> None:
    """Stop production, copy each pair, start production again.

    Raises StagingDataError or DockerError naming what failed. Production
    is started again whatever happens, including a failed or interrupted
    stop; staging is left created but not started.
    """
    staging_running = _running(staging_compose_project(project))
    if staging_running:
        raise StagingDataError(
            f"staging containers are running ({', '.join(staging_running)}); "
            f"refusing to replace their data underneath them.")
    kinds = verify_plan(plan)
    stopped = _running(project)
    cause: BaseException | None = None
    try:
        if stopped:
            print(f"  Stopping production for the copy: {', '.join(stopped)}")
            _run(["docker", "stop", "-t", str(_STOP_TIMEOUT), *stopped], capture=True)
        for (src, dest), is_file in zip(plan.pairs, kinds):
            print(f"  Copying production {src.label} to staging {dest.label}...")
            _copy(project, src, dest, is_file)
    except BaseException as e:  # noqa: BLE001 - re-raised; kept as the cause
        cause = e
        raise
    finally:
        if stopped:
            _start_again(stopped, cause)
    for store in plan.fresh:
        print(f"  NOTE: staging {store.label} has no production source; it starts as it is.")
    for store in plan.unused:
        print(f"  NOTE: production {store.label} is not mounted by the staged release; not copied.")
