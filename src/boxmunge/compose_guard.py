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
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING


from boxmunge import bind_sources, chown_hold, compose_references, compose_resolve
from boxmunge import docker_containers, start_alerts
from boxmunge import compose_up_steps as up_steps
from boxmunge.bind_sources import BindSourceError
from boxmunge.compose_own_files import container_bind_problems
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.docker import compose_up, start_containers
from boxmunge.docker_run import DockerError
from boxmunge.intake import IntakeError, validate_release_tree
from boxmunge.legacy_stage import legacy_stage_refusal
from boxmunge.log import log_error
from boxmunge.notify import notify
from boxmunge.overlay_users import stale_containers_problem, stale_overlay_problem
from boxmunge.paths import RESERVED_PROJECT_NAMES
from boxmunge.redeploy_hint import redeploy_command
from boxmunge.release_txn import load_txn, stale_reason, start_refusal
from boxmunge.staged_release import (
    STAGING_OVERLAY, SlotError, load_slot, slot_dir, staging_target,
)
from boxmunge.staging_copies import foreign_copies
from boxmunge.staging_isolation import separation_problems

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


class ComposeRefused(DockerError):
    """A start refused because the project's files or mounts fail a check."""


def _refused(paths: BoxPaths, project_name: str, component: str, reason: str,
             *, tampering: bool = True) -> ComposeRefused:
    message = (f"Refused to start {project_name}: {reason.rstrip('.')}. Nothing was started "
               f"or recreated; its running containers were left as they are.")
    log_error(component, message, paths, project=project_name)
    now = datetime.now(timezone.utc)
    if not start_alerts.alerted_recently(paths, project_name, reason, now):
        hint = (" If you did not make this change, a container may have tampered with "
                "the project's files: inspect it before redeploying." if tampering else "")
        notify(paths, f"{project_name}: start refused", message + hint,
               component=component, project=project_name, priority=1)
        start_alerts.record(paths, project_name, reason, now)
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


def _refuse_stale_overlay(paths: BoxPaths, project_name: str, component: str,
                          compose_files: list[str], deploying: bool, txn: str | None) -> None:
    """A start that runs the overlay as it is, after the users record
    changed, would run a service as its old user (overlay_users). Deploys
    and the cores resuming an install write the overlay themselves."""
    if deploying or txn is not None:
        return
    if paths.project_compose_override(project_name).name not in compose_files:
        return
    problem = stale_overlay_problem(paths, project_name)
    if problem is not None:
        raise _refused(paths, project_name, component, problem, tampering=False)


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
        _, read_files = compose_references.walk_references(release / "compose.yml", (release,))
        read_files = [*read_files, *(Path(f) for f in target.files)]
        model = compose_resolve.resolve_deployed_config(
            target.cwd, target.files, target.project_name, all_profiles=True,
            project_directory=target.project_directory, env_file=target.env_file)
        read_files += compose_resolve.model_env_files(model, target.project_directory or release)
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
                                       control_root=release, redo=f"stage {project_name} again")
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
    sha256 of every file boxmunge reads (those the reference walk found and
    the env files of the resolved model), instead of comparing them with the
    record; missing sources are created first.

    Unless `deploying`, the project's EXISTING containers' bind mounts are
    inspected too (stale_containers): a project deployed before these rules
    whose container already mounts the project directory, or a control
    file, read-write is refused — a plain restart would just re-run the
    compromised mount. `deploying` callers replace every container from the
    checked files (deploy, promote and stage install a freshly validated
    release; resume recreates what stale_containers names) or start none
    (the upgrade's record of a paused or quarantined project, whose own
    start checks them).

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
    _refuse_stale_overlay(paths, project_name, component, compose_files, deploying, txn)
    try:
        validate_release_tree(project_dir, project_name, paths, component,
                              lenient_values=True)
        _, read_files = compose_references.walk_references(
            project_dir / compose_files[0], (project_dir,))
        if not deploying:
            problems = _container_problems(project_name, project_dir, read_files)
            if problems:
                raise BindSourceError(problems[0] + _REDEPLOY)
        model = compose_resolve.resolve_deployed_config(
            project_dir, compose_files, project_name, all_profiles=True)
        read_files = [*read_files, *compose_resolve.model_env_files(model, project_dir)]
        sources = bind_sources.model_sources(model, project_dir)
        if record:
            bind_sources.record(project_dir, sources, read_files, record_path)
        else:
            rec = bind_sources.read_record(record_path)
            bind_sources.check_sources(project_dir, sources, rec["sources"])
            bind_sources.check_control(project_dir, read_files, rec["control"],
                                       redo=f"prod-deploy {project_name}")
    except (IntakeError, compose_resolve.ComposeResolveError, BindSourceError, OSError) as e:
        raise _refused(paths, project_name, component, str(e)) from e


# A container_bind_problems refusal: the containers must be replaced, which a
# deploy does (resume does it itself: stale_containers).
_REDEPLOY = " The project's containers hold this mount; redeploy to replace it."


def _container_problems(project_name: str, project_dir: Path,
                        read_files: list[Path]) -> list[str]:
    existing = docker_containers.container_bind_sources(project_name)
    return container_bind_problems(existing, project_dir, read_files)


def stale_containers(paths: BoxPaths, project_name: str, *, component: str,
                     compose_files: list[str]) -> str | None:
    """Why the project's existing containers must be recreated rather than
    started again (a mount the own-file rules refuse, made before them), or
    None. The files are checked by check_start either way; a start that
    recreates passes `deploying` and `force_recreate`. Raises ComposeRefused
    when the compose files cannot be read, DockerError when Docker cannot
    be asked."""
    project_dir = paths.project_dir(project_name)
    try:
        _, read_files = compose_references.walk_references(
            project_dir / compose_files[0], (project_dir,))
    except (compose_resolve.ComposeResolveError, OSError) as e:
        raise _refused(paths, project_name, component, str(e)) from e
    problems = _container_problems(project_name, project_dir, read_files)
    return problems[0] if problems else None


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
    back a platform name it lost first (compose_up_steps). A start
    whose image is missing is refused, naming it. A running container whose
    image the local image store no longer has is recreated
    (compose_up_steps). Raises ComposeRefused, compose_up_steps.ComposeUpFailed once
    the up has run, or DockerError before it."""
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
    up_steps.restore_build_names(paths, project_name, compose_project, overlay, component)
    redo = f"stage {project_name}" if staging else redeploy_command(paths, project_name)
    try:
        images = up_steps.start_images(run_dir, files, compose_project, services, where)
    except compose_resolve.ComposeResolveError as e:
        raise _refused(paths, project_name, component, str(e)) from e
    # Before the up: Compose creates in dependency order and fails only at
    # the service whose image is missing, after those ahead of it.
    missing = docker_containers.absent_images(images)
    if missing:
        raise _refused(paths, project_name, component, up_steps.missing_text(missing)
                       + f": a start runs only images a deploy built or pulled; run {redo}",
                       tampering=False)
    try:
        up(force_recreate=force_recreate, services=services)
    except DockerError as e:
        raise up_steps.up_failed(e, images, redo) from e
    try:
        up_steps.recreate_without_image(paths, project_name, compose_project, component,
                                        services, up)
    except DockerError as e:
        raise up_steps.ComposeUpFailed(str(e)) from e
    if not staging and start:
        # `services` brings up those they depend on too (start_images).
        chown_hold.after_start(paths, project_name,
                               None if services is None else sorted(images), component)
    # A partial up (restore's one service) may leave the rest stopped.
    if not staging and start and not services:
        up_steps.clear_copy_stop(paths, project_name, component)
        up_steps.sweep_live_scripts(paths, project_name, component)


def check_containers_start(paths: BoxPaths, project_name: str, names: list[str], *,
                           component: str) -> None:
    """Check what starting production's existing, stopped containers would
    mount. A `docker start` reads no compose file — it mounts what each
    container was created with — so only the containers' own bind mounts
    are checked: the own-file and nesting rules, and each source walked
    without following links, of the kind recorded at deploy. The containers
    to start (`names`) must run as the users record says. Raises
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
            raise BindSourceError(problems[0] + _REDEPLOY)
        sources = {bind_sources.project_rel(src, project_dir) for src, _rw in existing}
        rec = bind_sources.read_record(paths.project_bind_record(project_name))
        bind_sources.check_sources(project_dir, sources, rec["sources"])
    except (BindSourceError, OSError) as e:
        raise _refused(paths, project_name, component, str(e)) from e
    if paths.project_users_record(project_name).exists():
        starting = {c.service for c in docker_containers.project_containers(project_name)
                    if c.name in names}
        created = {svc: user for svc, user in
                   docker_containers.container_users(project_name).items() if svc in starting}
        stale = stale_containers_problem(paths, project_name, created)
        if stale is not None:
            raise _refused(paths, project_name, component, stale, tampering=False)


def start_containers_checked(
    paths: BoxPaths, project_name: str, names: list[str], *, component: str,
) -> None:
    """check_containers_start, then `docker start` the named containers.
    Raises ComposeRefused or DockerError."""
    check_containers_start(paths, project_name, names, component=component)
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
