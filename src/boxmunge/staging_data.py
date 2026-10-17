# SPDX-License-Identifier: Apache-2.0
"""Copy production's data into staging's stores (``staging.copy_data``).

The copy runs only while both sides are quiescent: production's running
containers are stopped for it and started again afterwards, whatever
happens, and staging must have no running container (its containers exist,
created but not started, so Compose has made its volumes). Every source
must exist: Docker would otherwise create an empty volume and the copy
would "succeed" with no data. Each destination is emptied completely,
hidden entries included, before the source is copied in.

Before production is stopped, the slot's production_stopped marker
records the containers durably (production_stopped), so a crash anywhere
in the copy leaves a marker whoever finds it acts on; once production runs
again the marker is cleared.

Every copy and removal runs in the data helper (data_helper): the data
belongs to container users, and on a remapped box to host ids deploy can
neither read nor write. Production's stores are mounted read-only.
"""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boxmunge import docker_containers
from boxmunge.compose_guard import check_containers_start, start_containers_checked
from boxmunge.data_helper import EMPTY_X, run_helper
from boxmunge.docker import staging_compose_project
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.production_stopped import ProductionDownError, mark_stopped, start_again
from boxmunge.release import project_data_dirs
from boxmunge.staged_release import load_slot
from boxmunge.staging_copy_plan import (
    CopyPlan, StagingDataError, Store, copy_sources, plan_copy, stores,
)
from boxmunge.staging_placeholders import copy_label, make_placeholder
from boxmunge.userns.offset import RemapError, remap_offset

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

__all__ = ["ProductionDownError", "StagingDataError", "copy_production_data",
           "plan_staging_copy", "prepare_destinations"]

_STOP_TIMEOUT = 15
_EMPTY_DST = EMPTY_X.replace("/x", "/dst")


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


def _remapped(paths: BoxPaths) -> bool:
    try:
        return remap_offset(paths) != 0
    except RemapError as e:
        raise StagingDataError(f"cannot tell whether the box is remapped, so nothing was "
                               f"copied: {e}") from e


def _refuse_top_level_files(paths: BoxPaths, project: str, plan: CopyPlan,
                            kinds: list[bool]) -> None:
    """A single-file store directly in the project directory is copied by
    replacing a file there, which no container can do on a remapped box
    (the directory is deploy's). Refused before anything changes."""
    project_dir = paths.project_dir(project)
    files = [src.key for (src, dest), is_file in zip(plan.pairs, kinds)
             if is_file and dest.kind == "bind" and Path(dest.ref).parent == project_dir]
    if files and _remapped(paths):
        raise StagingDataError(
            f"staging cannot copy production's single-file store {', '.join(files)} on a "
            f"remapped box: the copy would have to write into the project directory, "
            f"which containers cannot. Mount a directory holding the file instead "
            f"(e.g. ./db/app.db rather than ./app.db).")


def _top_entry(project_dir: Path, ref: str) -> tuple[Path, list[str]]:
    """The project directory's entry holding `ref`, and the parts below it.

    Docker resolves a -v source's links on the host as root, and data
    directories are written by containers, so only a top entry is mounted
    (no container can write the project directory itself); the rest is
    resolved inside the helper (_resolved)."""
    rel = Path(os.path.relpath(ref, project_dir))
    if not rel.parts or rel.parts[0] in (".", "..") or ".." in rel.parts:
        raise StagingDataError(f"{ref} is not inside {project_dir}; refusing to copy it")
    top = project_dir / rel.parts[0]
    if top.is_symlink():
        raise StagingDataError(f"{top} is a symlink; refusing to copy through it. "
                               f"Remove it (rm {top}) and stage again.")
    return top, list(rel.parts[1:])


def _resolved(var: str, path: str) -> str:
    """Shell that sets `var` to `path` and refuses it unless it exists and
    is reached without a link (resolved in the helper's own namespace)."""
    return (f'{var}={shlex.quote(path)} && [ -e "${var}" ] && '
            f'[ "$(readlink -f "${var}")" = "${var}" ] || {{ echo "{path} is missing or '
            f'reached through a symlink; nothing copied" >&2; exit 3; }}; ')


def _source(project_dir: Path, src: Store) -> tuple[list[str], str]:
    """Production's store, mounted read-only, and the shell that finds it as $s."""
    if src.kind == "volume":
        return _mount(src, "/src", True), "s=/src; "
    top, rest = _top_entry(project_dir, src.ref)
    return ["-v", f"{top}:/srcroot:ro"], _resolved("s", "/".join(["/srcroot", *rest]))


def _copy_job(project_dir: Path, src: Store, dest: Store,
              is_file: bool) -> tuple[list[str], str]:
    """The helper's mounts and script for one pair, planned (and every link
    on the host side refused) before production is stopped."""
    mounts, script = _source(project_dir, src)
    if dest.kind == "volume":  # exists (verified)
        return ([*mounts, *_mount(dest, "/dst", False)],
                f'{script}{_EMPTY_DST} && cp -a "$s"/. /dst/')
    rel = Path(os.path.relpath(dest.ref, project_dir))
    if is_file and len(rel.parts) == 1:
        # A file directly in the project directory: mount that directory,
        # which no container can write, and replace the file whole.
        name = shlex.quote(rel.parts[0])
        return ([*mounts, "-v", f"{project_dir}:/dst"],
                f'{script}rm -rf /dst/{name} && cp -a "$s" /dst/{name}')
    top, rest = _top_entry(project_dir, dest.ref)
    mounts += ["-v", f"{top}:/dst"]
    if is_file:
        name = shlex.quote(rest[-1])
        return mounts, (f'{script}{_resolved("d", "/".join(["/dst", *rest[:-1]]))}'
                        f'rm -rf "$d"/{name} && cp -a "$s" "$d"/{name}')
    return mounts, (f'{script}{_resolved("d", "/".join(["/dst", *rest]))}'
                    f'rm -rf "$d"/* "$d"/.[!.]* "$d"/..?* && [ -z "$(ls -A "$d")" ] '
                    f'&& cp -a "$s"/. "$d"/')


def _remove_wrong_type(project: str, project_dir: Path, dest: Store, top: str,
                       rest: str, want: str) -> None:
    """Remove a staging destination of the wrong type: it is staging's own
    copy, about to be replaced, and could only have been left by an earlier
    failed copy (or by hand)."""
    have = "a directory" if os.path.isdir(dest.ref) else "a file"
    print(f"  NOTE: staging's {dest.ref} is {have}, but production's {dest.key} is "
          f"{want}; removing staging's copy before the copy replaces it.")
    if rest:
        run_helper(copy_label(project), ["-v", f"{project_dir / top}:/x"],
                   f"rm -rf /x/{shlex.quote(rest)}")
    elif os.path.isdir(dest.ref) and not os.path.islink(dest.ref):
        run_helper(copy_label(project), ["-v", f"{dest.ref}:/x"], EMPTY_X)
        os.rmdir(dest.ref)
    else:
        os.unlink(dest.ref)


def prepare_destinations(paths: BoxPaths, project: str, plan: CopyPlan) -> None:
    """Make each bind destination exist, as the type production's source is,
    before Compose creates staging's containers (it refuses a missing config
    or secret file, and would create any other missing source as a
    directory). The copy replaces these placeholders."""
    project_dir = paths.project_dir(project)
    kinds = [_is_file(src, "production") for src, _dest in plan.pairs]
    _refuse_top_level_files(paths, project, plan, kinds)
    remapped = _remapped(paths)
    for (src, dest), is_file in zip(plan.pairs, kinds):
        if dest.kind != "bind":
            continue
        top, _, rest = os.path.relpath(dest.ref, project_dir).partition(os.sep)
        holder = project_dir / top
        if rest and os.path.lexists(holder) and (holder.is_symlink() or not holder.is_dir()):
            raise StagingDataError(
                f"{holder} must be staging's directory of copies but is not a "
                f"directory. Remove it (rm -rf {holder}) and stage again.")
        if os.path.lexists(dest.ref):
            right = os.path.isfile(dest.ref) if is_file else os.path.isdir(dest.ref)
            if right and not os.path.islink(dest.ref):
                continue
            _remove_wrong_type(project, project_dir, dest, top, rest,
                               "a file" if is_file else "a directory")
        make_placeholder(project, project_dir, os.path.relpath(dest.ref, project_dir),
                         is_file, remapped=remapped)


def _running(compose_project: str) -> list[str]:
    return [c.name for c in docker_containers.project_containers(compose_project)
            if c.running]


def _mark_stopped(paths: BoxPaths, project: str, stopped: list[str]) -> None:
    """Record the stop in the slot, durably, before it happens: a failed
    write stops nothing."""
    meta = load_slot(paths, project)
    if meta is None:
        raise StagingDataError(
            f"{project} has no staged slot to record production's stop in, so "
            f"production was not stopped and nothing was copied. Stage again.")
    mark_stopped(paths, project, meta, stopped)


def _start_again_prestage(paths: BoxPaths, project: str, stopped: list[str]) -> None:
    """The interim stage layout has no slot, so no marker: start the
    stopped containers directly. It goes when stage builds the slot."""
    try:
        start_containers_checked(paths, project, stopped, component="stage")
    except DockerError as e:
        message = (f"PRODUCTION IS DOWN: its containers were stopped for the data "
                   f"copy and starting them again failed: {e}. Start them with: "
                   f"docker start {' '.join(stopped)}")
        print(f"ERROR: {message}", file=sys.stderr)
        raise ProductionDownError(message) from e
    print("  Production started again.")


def copy_production_data(paths: BoxPaths, project: str, plan: CopyPlan, *,
                         prestage: bool = False) -> None:
    """Stop production, copy each pair, start production again.

    Raises StagingDataError, DockerError or ProductionDownError naming what
    failed. Every pair is planned, and its links refused, before
    production stops. Production is not stopped if its containers' mounts
    would not be started again (compose_guard), nor before the slot's
    production_stopped marker is written. It is started again whatever
    happens, including a failed or interrupted stop (start_again, which
    clears the marker, or keeps it and says so loudly if the start fails);
    staging is left created but not started. `prestage` is the interim
    stage layout, which has no slot: no marker is written.
    """
    staging_running = _running(staging_compose_project(project))
    if staging_running:
        raise StagingDataError(
            f"staging containers are running ({', '.join(staging_running)}); "
            f"refusing to replace their data underneath them.")
    kinds = verify_plan(plan)
    _refuse_top_level_files(paths, project, plan, kinds)
    project_dir = paths.project_dir(project)
    jobs = [_copy_job(project_dir, src, dest, is_file)
            for (src, dest), is_file in zip(plan.pairs, kinds)]
    stopped = _running(project)
    if stopped:
        check_containers_start(paths, project, component="stage")
        if not prestage:
            _mark_stopped(paths, project, stopped)
    try:
        if stopped:
            print(f"  Stopping production for the copy: {', '.join(stopped)}")
            _run(["docker", "stop", "-t", str(_STOP_TIMEOUT), *stopped], capture=True)
        for (src, dest), (mounts, script) in zip(plan.pairs, jobs):
            print(f"  Copying production {src.label} to staging {dest.label}...")
            run_helper(copy_label(project), mounts, script)
    finally:
        if stopped and prestage:
            _start_again_prestage(paths, project, stopped)
        elif stopped:
            start_again(paths, project, component="stage", alert=False)
    for store in plan.fresh:
        print(f"  NOTE: staging {store.label} has no production source; it starts as it is.")
    for store in plan.unused:
        print(f"  NOTE: production {store.label} is not mounted by the staged release; not copied.")
