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

While a release is staged, the project directory holds the staged
release's files, not production's, so a production start other than the
promote that deploys it is refused too: it would recreate production from
the staged release (and run its migrations on production data).

While an install transaction is open (.releases/install.json), a
production start is refused unless it is the core resuming that install:
the project directory may hold a half-installed release.

A start that fails a check does not happen: the refusal is logged, the
operator is alerted, and the running containers are left as they are.
ComposeRefused is a DockerError, so every caller already treats it as a
failed start.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge import bind_sources, compose_resolve, docker_containers
from boxmunge.bind_sources import BindSourceError
from boxmunge.compose_own_files import container_bind_problems
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.docker import compose_up, staging_compose_project, start_containers
from boxmunge.docker_run import DockerError
from boxmunge.intake import IntakeError, validate_release_tree
from boxmunge.log import log_error
from boxmunge.notify import notify
from boxmunge.paths import RESERVED_PROJECT_NAMES
from boxmunge.release_staging import has_prestage
from boxmunge.release_txn import load_txn, stale_reason, start_refusal
from boxmunge.staged_release import SlotError, clear_production_stopped

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
    path.parent.mkdir(parents=True, exist_ok=True)
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
    reason = start_refusal(project_name, open_txn, stale_reason(paths, project_name, open_txn))
    raise _refused(paths, project_name, component, reason, tampering=False)


def check_start(
    paths: BoxPaths, project_name: str, *, component: str, compose_files: list[str],
    staging: bool = False, record: bool = False, promoting: bool = False,
    deploying: bool = False, txn: str | None = None,
) -> None:
    """Re-validate the project and check every bind source it would mount.

    A production start while an install transaction is open is refused
    unless `txn` is that transaction's id (the core resuming it). A
    production start while a release is staged is refused unless it is
    `promoting` that release.

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
    project_dir = paths.project_dir(project_name)
    compose_project = staging_compose_project(project_name) if staging else project_name
    record_path = paths.project_bind_record(project_name, staging=staging)
    if not staging:
        _refuse_if_install_open(paths, project_name, component, txn)
    if not (staging or promoting) and has_prestage(paths, project_name):
        raise _refused(paths, project_name, component,
                       "a release is staged, so the project directory holds the staged "
                       "release, not production's; promote or unstage first")
    try:
        validate_release_tree(project_dir, project_name, paths, component)
        _, read_files = compose_resolve.walk_references(
            project_dir / compose_files[0], (project_dir,))
        existing = docker_containers.container_bind_sources(compose_project)
        if not deploying:
            problems = container_bind_problems(existing, project_dir, read_files)
            if problems:
                raise BindSourceError(problems[0])
        model = compose_resolve.resolve_deployed_config(
            project_dir, compose_files, compose_project, all_profiles=True)
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
    paths: BoxPaths, project_name: str, *, component: str, compose_files: list[str],
    staging: bool = False, record: bool = False, promoting: bool = False,
    deploying: bool = False, build: bool = True, force_recreate: bool = False,
    services: list[str] | None = None, start: bool = True, txn: str | None = None,
) -> None:
    """check_start, then `docker compose up` (`start=False`: create without
    starting, which still mounts nothing yet but fixes every bind source in
    the containers it creates). Raises ComposeRefused or DockerError."""
    check_start(paths, project_name, component=component, compose_files=compose_files,
                staging=staging, record=record, promoting=promoting, deploying=deploying,
                txn=txn)
    compose_up(paths.project_dir(project_name), compose_files=compose_files, build=build,
               project_name=staging_compose_project(project_name) if staging else project_name,
               force_recreate=force_recreate, services=services, start=start)
    if not staging and start:
        _clear_production_stopped(paths, project_name, component)


def _clear_production_stopped(paths: BoxPaths, project_name: str, component: str) -> None:
    """Production runs again, so a staging copy's stop no longer stands
    (boxmunge.production_stopped). Production is up by now: an unreadable
    slot must not turn that into a failed start, so it is said loudly and
    left for the slot's own cores, which refuse it."""
    try:
        clear_production_stopped(paths, project_name)
    except (SlotError, OSError) as e:
        message = (f"{project_name}: production is running, but its staged slot cannot be "
                   f"read to clear the production_stopped marker: {e}. Inspect the slot and "
                   f"unstage {project_name}.")
        print(f"ERROR: {message}", file=sys.stderr)
        log_error(component, message, paths, project=project_name)


def check_containers_start(paths: BoxPaths, project_name: str, *, component: str) -> None:
    """Check what starting production's existing, stopped containers would
    mount. A `docker start` reads no compose file — it mounts what each
    container was created with, and during a stage the compose files on
    disk are the staged release's — so only the containers' own bind mounts
    are checked: the own-file and nesting rules, and each source walked
    without following links, of the kind recorded at deploy. Raises
    ComposeRefused, also while an install transaction is open (no install
    resumes by restarting stopped containers)."""
    _refuse_if_install_open(paths, project_name, component, None)
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
                      build: bool = True, force_recreate: bool = False,
                      services: list[str] | None = None) -> None:
    """`docker compose up` for the self-test canary, without the project checks.

    The canary is boxmunge's own fixture, copied fresh from the installed
    release by `self-test` and torn down after it. It publishes a host
    port, which no project may, so it cannot pass them. Only `restore`
    called by `self-test` uses this.
    """
    compose_up(paths.project_dir(project_name), compose_files=compose_files, build=build,
               project_name=project_name, force_recreate=force_recreate, services=services)
