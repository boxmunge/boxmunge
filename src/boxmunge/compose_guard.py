# SPDX-License-Identifier: Apache-2.0
"""The only way boxmunge starts or recreates a project's containers.

Deploy validates a project's compose file, but root starts it again long
after: upgrades restart every project, container updates and CVE resumes
recreate them, `recover`, `resume`, `restore` and `stage` start them. The
files in the project directory may have changed by then, and Docker
follows symlinks in bind sources when it mounts them. So every start
first re-runs deploy's own validation (`validate_release_tree`) on the
files on disk and checks every bind source of the compose model it is
about to run (see boxmunge.bind_sources).

A stage left by boxmunge 0.10.1 (boxmunge.legacy_stage) put the staged
release's files in the project directory, so every production start of
such a project is refused: it could recreate production from the staged
release (and run its migrations on production data). A stage in the slot
leaves the project directory as production's, so production starts as
usual.

While an install transaction is open (.releases/install.json), a
production start is refused unless it is the core resuming that install:
the project directory may hold a half-installed release.

Staging runs from the slot (.releases/staged): its starts validate the
staged release there, resolve its model from it, and prove that model
mounts nothing of production's (I3, staging_isolation) before Compose
runs.

A start that fails a check does not happen: the refusal is logged, the
operator is alerted, and the running containers are left as they are.
ComposeRefused is a DockerError, so every caller already treats it as a
failed start.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from boxmunge import bind_sources, built_images, compose_resolve, docker_containers
from boxmunge.bind_sources import BindSourceError
from boxmunge.compose_images import built_image_name
from boxmunge.compose_own_files import container_bind_problems
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.docker import compose_up, start_containers
from boxmunge.docker_run import DockerError
from boxmunge.fileutil import discard_dir
from boxmunge.fs_nofollow import mkdir_p_deploy, read_text_nofollow
from boxmunge.intake import IntakeError, validate_release_tree
from boxmunge.legacy_stage import legacy_stage_refusal
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.paths import RESERVED_PROJECT_NAMES
from boxmunge.redeploy_hint import redeploy_command
from boxmunge.release_txn import load_txn, stale_reason, start_refusal
from boxmunge.staged_release import (
    STAGING_OVERLAY, SlotError, clear_production_stopped, load_slot, slot_dir, staging_target,
)
from boxmunge.staging_copies import foreign_copies
from boxmunge.staging_isolation import separation_problems

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


class ComposeRefused(DockerError):
    """A start refused because the project's files or mounts fail a check."""


# A persistently tampered project is checked on every timer tick (container
# update daily, health every few minutes); without this an operator is paged
# on each one. The refusal is always logged; the alert repeats only this
# often per project and reason.
_ALERT_INTERVAL = timedelta(hours=24)


def _alert_recently(paths: BoxPaths, project_name: str, reason: str, now: datetime) -> bool:
    path = paths.state / "start-refused" / f"{project_name}.json"
    key = hashlib.sha256(reason.encode()).hexdigest()[:16]
    try:
        doc = json.loads(path.read_text())
        last = datetime.fromisoformat(doc[key])
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return last.tzinfo is not None and now - last < _ALERT_INTERVAL


def _record_alert(paths: BoxPaths, project_name: str, reason: str, now: datetime) -> None:
    path = paths.state / "start-refused" / f"{project_name}.json"
    key = hashlib.sha256(reason.encode()).hexdigest()[:16]
    mkdir_p_deploy(path.parent)
    try:
        doc = json.loads(path.read_text())
        if not isinstance(doc, dict):
            doc = {}
    except (OSError, ValueError):
        doc = {}
    doc[key] = now.isoformat()
    from boxmunge.fileutil import atomic_write_text
    atomic_write_text(path, json.dumps(doc) + "\n")


def _refused(paths: BoxPaths, project_name: str, component: str, reason: str,
             *, tampering: bool = True) -> ComposeRefused:
    message = (f"Refused to start {project_name}: {reason}. Nothing was started "
               f"or recreated; its running containers were left as they are.")
    log_error(component, message, paths, project=project_name)
    now = datetime.now(timezone.utc)
    if not _alert_recently(paths, project_name, reason, now):
        hint = (" If you did not make this change, a container may have tampered with "
                "the project's files: inspect it before redeploying." if tampering else "")
        notify(paths, f"{project_name}: start refused", message + hint,
               component=component, project=project_name, priority=1)
        _record_alert(paths, project_name, reason, now)
    return ComposeRefused(message)


def _refuse_if_install_open(paths: BoxPaths, project_name: str, component: str,
                            txn: str | None) -> None:
    """Production starts wait for an open install: only the core resuming it
    (which passes its id) may start production. The reason names the
    install's ref and phase, so the alert repeats once per transaction and
    then every _ALERT_INTERVAL."""
    try:
        open_txn = load_txn(paths, project_name)
    except ReleaseStateError as e:
        raise _refused(paths, project_name, component, str(e), tampering=False) from e
    if open_txn is None or open_txn.id == txn:
        return
    reason = start_refusal(paths, project_name, open_txn, stale_reason(paths, project_name, open_txn))
    raise _refused(paths, project_name, component, reason, tampering=False)


def _refuse_if_legacy_stage(paths: BoxPaths, project_name: str, component: str) -> None:
    refusal = legacy_stage_refusal(paths, project_name)
    if refusal is not None:
        raise _refused(paths, project_name, component, refusal, tampering=False)


def _check_staging(paths: BoxPaths, project_name: str, *, component: str,
                   record: bool) -> None:
    """Staging runs from the slot: validate the staged release there,
    resolve the model from it, prove I3 on that model, and check (or record)
    its bind sources against the project dir as staging's own record, whose
    control files are the slot's (a production deploy during the stage
    changes none of them)."""
    project_dir = paths.project_dir(project_name)
    try:
        meta = load_slot(paths, project_name)
    except SlotError as e:
        raise _refused(paths, project_name, component, f"its staged slot is unusable: {e}; "
                       f"unstage {project_name}, or stage again") from e
    if meta is None:
        raise _refused(paths, project_name, component,
                       f"nothing is staged for {project_name}", tampering=False)
    target = staging_target(paths, project_name)
    release = target.cwd
    try:
        validate_release_tree(release, project_name, paths, component)
        _, read_files = compose_resolve.walk_references(release / "compose.yml", (release,))
        read_files = [*read_files, *(Path(f) for f in target.files)]
        model = compose_resolve.resolve_deployed_config(
            target.cwd, target.files, target.project_name, all_profiles=True,
            project_directory=target.project_directory, env_file=target.env_file)
        problems = separation_problems(model, project_dir, release,
                                       foreign_copies(project_dir, meta.made))
        if problems:
            raise BindSourceError(problems[0])
        sources = bind_sources.model_sources(model, project_dir)
        record_path = paths.project_bind_record(project_name, staging=True)
        if record:
            bind_sources.record(project_dir, sources, read_files, record_path,
                                control_root=release)
        else:
            rec = bind_sources.read_record(record_path)
            bind_sources.check_sources(project_dir, sources, rec["sources"])
            bind_sources.check_control(project_dir, read_files, rec["control"],
                                       control_root=release)
    except (IntakeError, compose_resolve.ComposeResolveError, BindSourceError, OSError,
            ReleaseStateError) as e:
        raise _refused(paths, project_name, component, str(e)) from e


def check_start(
    paths: BoxPaths, project_name: str, *, component: str,
    compose_files: list[str] | None = None, staging: bool = False, record: bool = False,
    deploying: bool = False, txn: str | None = None,
) -> None:
    """Re-validate the project and check every bind source it would mount.

    A `staging` start is checked against the slot (_check_staging), with
    staging's compose files; `compose_files` and `txn` are production's and
    mean nothing there. A production start needs `compose_files`.

    A production start while an install transaction is open is refused
    unless `txn` is that transaction's id (the core resuming it). A
    production start of a project staged by boxmunge 0.10.1 is refused.

    `record` (deploy, stage, upgrade) records the sources' kinds and the
    sha256 of every file boxmunge reads, instead of comparing them with the
    record; missing sources are created first.

    Unless `deploying` (deploy, promote and stage install a freshly
    validated release and recreate every container from it), the project's
    EXISTING containers' bind mounts are inspected too: a project deployed
    before these rules whose container already mounts the project directory,
    or a control file, read-write is refused — a plain restart would just
    re-run the compromised mount, so a redeploy is required.

    Raises ComposeRefused.
    """
    if staging:
        if compose_files is not None or txn is not None:
            raise ValueError("a staging start runs the slot's own files and no install "
                             "transaction; pass neither compose_files nor txn")
        _check_staging(paths, project_name, component=component, record=record)
        return
    if compose_files is None:
        raise ValueError("a production start check needs compose_files")
    project_dir = paths.project_dir(project_name)
    record_path = paths.project_bind_record(project_name)
    _refuse_if_install_open(paths, project_name, component, txn)
    _refuse_if_legacy_stage(paths, project_name, component)
    try:
        validate_release_tree(project_dir, project_name, paths, component,
                              lenient_values=True)
        _, read_files = compose_resolve.walk_references(
            project_dir / compose_files[0], (project_dir,))
        existing = docker_containers.container_bind_sources(project_name)
        if not deploying:
            problems = container_bind_problems(existing, project_dir, read_files)
            if problems:
                raise BindSourceError(problems[0])
        model = compose_resolve.resolve_deployed_config(
            project_dir, compose_files, project_name, all_profiles=True)
        sources = bind_sources.model_sources(model, project_dir)
        if record:
            bind_sources.record(project_dir, sources, read_files, record_path)
        else:
            rec = bind_sources.read_record(record_path)
            bind_sources.check_sources(project_dir, sources, rec["sources"])
            bind_sources.check_control(project_dir, read_files, rec["control"])
    except (IntakeError, compose_resolve.ComposeResolveError, BindSourceError, OSError) as e:
        raise _refused(paths, project_name, component, str(e)) from e


def compose_up_checked(
    paths: BoxPaths, project_name: str, *, component: str,
    compose_files: list[str] | None = None, staging: bool = False, record: bool = False,
    deploying: bool = False,
    force_recreate: bool = False, services: list[str] | None = None, start: bool = True,
    txn: str | None = None,
) -> None:
    """check_start, then `docker compose up` (`start=False`: create without
    starting, which still mounts nothing yet but fixes every bind source in
    the containers it creates). Staging runs from the slot, with its own
    files. A production up of every service clears the slot's
    production_stopped marker and sweeps 0.10.1's live-scripts copy.

    No start pulls or builds (`--pull never --no-build`, whatever a
    service's `pull_policy` says): it runs only the local images a deploy
    (or stage) built, pulled and decided users for, or that container-update
    pulled and checked. The image a build service's container runs gets
    back a platform name it lost first (_name_running_builds). A start
    whose image is missing is refused, naming it. A running container whose
    image the local image store no longer has is recreated
    (_recreate_without_image). Raises ComposeRefused or DockerError."""
    check_start(paths, project_name, component=component, compose_files=compose_files,
                staging=staging, record=record, deploying=deploying, txn=txn)
    if staging:
        target = staging_target(paths, project_name)
        where = {"project_dir": target.cwd, "project_directory": target.project_directory,
                 "env_file": target.env_file}
        files, compose_project = list(target.files), target.project_name
        overlay = slot_dir(paths, project_name) / STAGING_OVERLAY
    else:
        where = {"project_dir": paths.project_dir(project_name)}
        files, compose_project = list(compose_files or []), project_name
        overlay = paths.project_compose_override(project_name)
        if overlay.name not in files:
            overlay = None
    run_dir = where.pop("project_dir")
    up = functools.partial(compose_up, run_dir, compose_files=files, build=False,
                           project_name=compose_project, start=start, pinned=True, **where)
    _name_running_builds(paths, project_name, compose_project, overlay, component)
    redo = f"stage {project_name}" if staging else redeploy_command(paths, project_name)
    try:
        images = _start_images(run_dir, files, compose_project, services, where)
    except compose_resolve.ComposeResolveError as e:
        raise _refused(paths, project_name, component, str(e)) from e
    # Before the up: Compose creates in dependency order and fails only at
    # the service whose image is missing, after those ahead of it.
    missing = docker_containers.absent_images(images)
    if missing:
        raise _refused(paths, project_name, component, _missing_text(missing)
                       + f": a start runs only images a deploy built or pulled; run {redo}",
                       tampering=False)
    try:
        up(force_recreate=force_recreate, services=services)
    except DockerError as e:
        gone = docker_containers.absent_images(images)
        if not gone:
            raise
        raise DockerError(
            f"{e}. {_missing_text(gone)}: it went from the local image store during the "
            f"start, which may already have created or recreated the services ahead of "
            f"it. Run {redo}.") from e
    _recreate_without_image(paths, project_name, compose_project, component, services, up)
    # A partial up (restore's one service) may leave the rest stopped.
    if not staging and start and not services:
        _clear_production_stopped(paths, project_name, component)
        _sweep_live_scripts(paths, project_name, component)


def _name_running_builds(paths: BoxPaths, project_name: str, compose_project: str,
                         overlay: Path | None, component: str) -> None:
    """Name the images the build services' containers run by their platform
    name where it names nothing (built_images.name_running_builds), so the
    start runs them instead of building new ones. The overlay says which
    services are built: it gives each one its platform name (an overlay
    from before boxmunge named built images gives none; a start without
    one has none to name)."""
    if overlay is None:
        return
    try:
        doc = yaml.safe_load(read_text_nofollow(overlay)) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise DockerError(f"cannot read {overlay}: {e}") from e
    services = doc.get("services") if isinstance(doc, dict) else None
    built = sorted(svc for svc, spec in (services or {}).items()
                   if isinstance(spec, dict)
                   and spec.get("image") == built_image_name(compose_project, svc))
    named = built_images.name_running_builds(compose_project, built) if built else []
    if named:
        log_operation(component, f"named the images {compose_project}'s containers run: "
                      f"{', '.join(named)} (their old names had been taken off them)",
                      paths, project=project_name)


def _missing_text(missing: list[tuple[str, str]]) -> str:
    return "; ".join(f"the image for {svc} ({image}) is missing" for svc, image in missing)


def _start_images(run_dir: Path, files: list[str], compose_project: str,
                  services: list[str] | None, where: dict) -> dict[str, str]:
    """{service: image} for every service the up would create or start:
    `services`, or every service without a profile (boxmunge runs Compose
    with no profile enabled), and those they depend on. Compose names a
    build service without an `image:` (an overlay from before boxmunge
    named built images) `<project>-<service>`."""
    model = compose_resolve.resolve_deployed_config(
        run_dir, files, compose_project, all_profiles=True, **where)
    specs = model.get("services") or {}
    wanted: set[str] = set()
    todo = list(services if services is not None else
                (svc for svc, spec in specs.items()
                 if isinstance(spec, dict) and not spec.get("profiles")))
    while todo:
        svc = todo.pop()
        spec = specs.get(svc)
        if svc in wanted or not isinstance(spec, dict):
            continue
        wanted.add(svc)
        todo.extend(spec.get("depends_on") or ())
    images = {}
    for svc in sorted(wanted):
        spec = specs[svc]
        image = spec.get("image") or (f"{compose_project}-{svc}" if "build" in spec else None)
        if isinstance(image, str):
            images[svc] = image
    return images


def _recreate_without_image(paths: BoxPaths, project_name: str, compose_project: str,
                            component: str, services: list[str] | None,
                            up: Callable[..., None]) -> None:
    """Recreate the running containers whose image the local image store no
    longer has, from the image their name points at now.

    A build that moved a name to a new image index left them there:
    Compose compares the platform manifest, which a cached build keeps, so
    it does not recreate them, and on the containerd store the index they
    were created from goes with its last name (boxmunge.docker_containers).
    Compose left them because their platform manifest is still the one
    the name points at, so the recreated containers run the same image."""
    gone = docker_containers.running_without_image(compose_project)
    recreate = sorted(svc for svc in gone if services is None or svc in services)
    if not recreate:
        return
    names = ", ".join(n for svc in recreate for n in gone[svc])
    message = (f"{compose_project}: recreating {', '.join(recreate)}: the local image store "
               f"no longer has the image {names} was created from (a build replaced it "
               f"under its name)")
    print(f"  WARNING: {message}", file=sys.stderr)
    log_warning(component, message, paths, project=project_name)
    up(force_recreate=True, services=recreate)


def _clear_production_stopped(paths: BoxPaths, project_name: str, component: str) -> None:
    """Production runs again, so a staging copy's stop no longer stands
    (boxmunge.production_stopped). Production is up by now: an unreadable
    slot must not turn that into a failed start, so it is said loudly and
    left for the slot's own cores, which refuse it."""
    try:
        clear_production_stopped(paths, project_name)
    except (SlotError, OSError) as e:
        message = (f"{project_name}: production is running, but its staged slot cannot be "
                   f"read or written to clear the production_stopped marker: {e}. Inspect "
                   f"the slot and unstage {project_name}.")
        print(f"ERROR: {message}", file=sys.stderr)
        log_error(component, message, paths, project=project_name)
        notify(paths, f"{project_name}: staged slot unreadable", message,
               component=component, project=project_name, priority=1)


# The bind source boxmunge 0.10.1's production overlay used for the copy.
LIVE_SCRIPTS_SOURCE = "./.releases/live-scripts"


def _sweep_live_scripts(paths: BoxPaths, project_name: str, component: str) -> None:
    """boxmunge 0.10.1 mounted production's smoke scripts from
    .releases/live-scripts. Once production's overlay no longer names it and
    no container of the project mounts it, it is removed. Production is up
    by now, so a failure to tell or to remove is said, not raised."""
    live = paths.project_releases(project_name) / "live-scripts"
    if not os.path.lexists(live):
        return
    try:
        overlay = paths.project_compose_override(project_name)
        if overlay.exists() and LIVE_SCRIPTS_SOURCE in overlay.read_text():
            return
        roots = {str(live), os.path.realpath(live)}
        if any(src == root or src.startswith(root + os.sep)
               for src, _rw in docker_containers.container_bind_sources(project_name)
               for root in roots):
            return
        discard_dir(live)
    except (OSError, DockerError) as e:
        message = (f"{project_name}: production is running, but {live} (the smoke-script "
                   f"copy boxmunge 0.10.1 mounted) was not removed: {e}. The next "
                   f"production start tries again; if it is not a directory, inspect it.")
        print(f"WARNING: {message}", file=sys.stderr)
        log_warning(component, message, paths, project=project_name)


def check_containers_start(paths: BoxPaths, project_name: str, *, component: str) -> None:
    """Check what starting production's existing, stopped containers would
    mount. A `docker start` reads no compose file — it mounts what each
    container was created with — so only the containers' own bind mounts
    are checked: the own-file and nesting rules, and each source walked
    without following links, of the kind recorded at deploy. Raises
    ComposeRefused, also while an install transaction is open (no install
    resumes by restarting stopped containers) and for a project staged by
    boxmunge 0.10.1, as check_start does."""
    _refuse_if_install_open(paths, project_name, component, None)
    _refuse_if_legacy_stage(paths, project_name, component)
    project_dir = paths.project_dir(project_name)
    try:
        existing = docker_containers.container_bind_sources(project_name)
        problems = container_bind_problems(existing, project_dir, [])
        if problems:
            raise BindSourceError(problems[0])
        sources = {bind_sources.project_rel(src, project_dir) for src, _rw in existing}
        rec = bind_sources.read_record(paths.project_bind_record(project_name))
        bind_sources.check_sources(project_dir, sources, rec["sources"])
    except (BindSourceError, OSError) as e:
        raise _refused(paths, project_name, component, str(e)) from e


def start_containers_checked(
    paths: BoxPaths, project_name: str, names: list[str], *, component: str,
) -> None:
    """check_containers_start, then `docker start` the named containers.
    Raises ComposeRefused or DockerError."""
    check_containers_start(paths, project_name, component=component)
    start_containers(names)


def compose_up_platform(stack_dir: Path, compose_files: list[str], stack: str, *,
                        build: bool) -> None:
    """`docker compose up` for one of the platform's own stacks (Caddy).

    Their compose files are boxmunge's, outside every project directory,
    and they mount no project's files, so there is no project to check.
    """
    if stack not in RESERVED_PROJECT_NAMES:
        raise ValueError(f"{stack!r} is not a platform stack; start projects with "
                         f"compose_up_checked")
    compose_up(stack_dir, compose_files=compose_files, build=build, project_name=stack)


def compose_up_canary(paths: BoxPaths, project_name: str, *, compose_files: list[str],
                      force_recreate: bool = False,
                      services: list[str] | None = None) -> None:
    """`docker compose up` for the self-test canary, without the project checks.

    The canary is boxmunge's own fixture, copied fresh from the installed
    release by `self-test` and torn down after it. It publishes a host
    port, which no project may, so it cannot pass them. Only `restore`
    called by `self-test` uses this. Like every start, it neither pulls nor
    builds: `self-test` built and pulled the canary's images when it
    brought it up.
    """
    compose_up(paths.project_dir(project_name), compose_files=compose_files, build=False,
               project_name=project_name, force_recreate=force_recreate, services=services,
               pinned=True)
