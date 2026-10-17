# SPDX-License-Identifier: Apache-2.0
"""Per-project steps of a platform upgrade.

migrate manifests and regenerate configs (upgrade_exclusions.apply_projects,
per project under its lock) -> (Caddy reload) -> restart projects.
upgrade_cmd sequences these for --apply and the full flow; check_upgrade is
the write-nothing rendering behind --dry-run.
"""

import os
from collections.abc import Collection
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from boxmunge.caddy import generate_caddy_config, prepare_caddy_config
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.compose import generate_compose_override, load_user_compose, prepare_compose_override
from boxmunge.compose_validate import validate_user_compose, ComposeSecurityError
from boxmunge.user_entries import USER_ENTRIES, split_user_entries
from boxmunge.compose_guard import ComposeRefused, check_start, compose_up_checked
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.release_txn import InstallTxn, load_txn, stale_reason, start_refusal
from boxmunge.docker import DockerError
from boxmunge.fileutil import atomic_write_text, project_lock, LockError
from boxmunge.legacy_stage import LegacyStage, cannot_tell_left_as_is, legacy_stage
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import (
    CURRENT_SCHEMA_VERSION, ManifestError, load_manifest_as_written, validate_manifest,
)
from boxmunge.git_layout import relink_advice, unlinked_files
from boxmunge.migration import migrate_manifest, MigrationError
from boxmunge.pause import render_maintenance_caddy_config
from boxmunge.fleet import report_project_failure
from boxmunge.paths import BoxPaths, InvalidProjectName, validate_project_name
from boxmunge.security_overlay import services_with_off_profile


class UpgradeGateError(Exception):
    """A step the upgrade cannot succeed without failed; the shim rolls back."""


def _project_dirs(paths: BoxPaths) -> Iterator[Path]:
    """Every addressable project directory with a manifest.yml (a dangling
    link included: loading it raises ManifestError).

    Callers let ManifestError propagate. A corrupted manifest means the
    project never gets its schema bumped or overlay regenerated; skipping it
    would let the upgrade report success over a stale project. The shim
    rolls back instead.
    """
    if not paths.projects.exists():
        return
    for project_dir in sorted(paths.projects.iterdir()):
        if (project_dir.is_dir() and os.path.lexists(project_dir / "manifest.yml")
                and _addressable(project_dir, paths)):
            yield project_dir


def require_manifest(project_dir: Path) -> Path:
    """The project's manifest.yml; ManifestError, with the fix, for a link
    whose target is missing. Only called for a project that is not excluded
    (exclusion() reads no manifest), so a legacy stage never fails here."""
    path = project_dir / "manifest.yml"
    if path.is_symlink() and not path.exists():
        raise ManifestError(
            f"{project_dir.name}: manifest.yml links to {os.readlink(path)}, which does not "
            f"exist; restore it in repo/ or delete the project, then retry the upgrade")
    return path


def exclusion(paths: BoxPaths, name: str) -> LegacyStage | InstallTxn | ReleaseStateError | OSError | None:
    """Why the upgrade leaves `name` exactly as it is, or None: a stage left by
    0.10.1, an OSError when it cannot be told whether one is on disk, an
    open install, or an install record this release cannot read. Read-only;
    the one decision behind the dry run and the apply."""
    try:
        stage = legacy_stage(paths, name)
    except OSError as e:
        return e
    if stage is not None:
        return stage
    try:
        return load_txn(paths, name)
    except ReleaseStateError as e:
        return e


def _unreadable_release_files(paths: BoxPaths, name: str, txn: InstallTxn) -> tuple[str | None, str | None]:
    """(stale_reason, None), or (None, why the release files the stale check
    reads cannot be read). The project is excluded either way, so an
    unreadable live.json or previous.json is reported, never fatal."""
    try:
        return stale_reason(paths, name, txn), None
    except (ReleaseStateError, OSError) as e:
        return None, (f"its release files cannot be read ({type(e).__name__}: {e}); "
                      f"inspect {paths.project_releases(name)}")


def install_exclusion_text(paths: BoxPaths, name: str, txn: InstallTxn) -> str:
    """Why the apply leaves a project with an open install as it is."""
    stale, unreadable = _unreadable_release_files(paths, name, txn)
    if unreadable is not None:
        return (f"an install of {txn.ref} ({txn.source}) is open at phase {txn.phase}; "
                f"{unreadable}")
    return start_refusal(name, txn, stale)


def _addressable(project_dir: Path, paths: BoxPaths) -> bool:
    """False, after reporting it, for a project directory whose name is no
    longer a valid project name (a reserved name such as `<x>-staging`).

    Such a project cannot be managed at all, and rolling the upgrade back
    would not change that, so it is reported loudly and the upgrade carries
    on with every other project.
    """
    try:
        validate_project_name(project_dir.name)
    except InvalidProjectName as e:
        report_project_failure("upgrade", project_dir.name, e, paths)
        return False
    return True


def _migrated(project_dir: Path, manifest: dict[str, Any]) -> dict[str, Any] | None:
    """The manifest migrated to the current schema and validated, or None if
    it is already current. Raises MigrationError if the result is invalid:
    a migration that produces a malformed manifest is a bug, and persisting
    it would only move the failure to the next deploy."""
    if manifest.get("schema_version", 1) == CURRENT_SCHEMA_VERSION:
        return None
    migrated = migrate_manifest(manifest, CURRENT_SCHEMA_VERSION)
    errors, _ = validate_manifest(migrated, expected_name=project_dir.name)
    if errors:
        raise MigrationError(
            f"Migrated manifest for {project_dir.name} failed validation. "
            f"Errors: {'; '.join(errors)}"
        )
    return migrated


@dataclass
class ManifestMigration:
    """Projects whose manifest is older than the current schema: `written`
    were migrated on disk; `in_memory` are git projects, whose manifest.yml
    links into the repository and is migrated by every reader instead.
    `unlinked` maps each git project whose manifest.yml or compose.yml is
    not a link into repo/ to the fix. Projects the apply left alone are in
    upgrade_exclusions.Exclusions."""
    written: list[str] = field(default_factory=list)
    in_memory: list[str] = field(default_factory=list)
    unlinked: dict[str, str] = field(default_factory=dict)


def _links_into_repository(project_dir: Path) -> bool:
    return (project_dir / "manifest.yml").is_symlink()


def compose_refusal(paths: BoxPaths, name: str, manifest: dict[str, Any]) -> str | None:
    """Why this release's compose validator refuses the project, or None.

    Pure: the dry run calls it too, and must log nothing.
    """
    off_services = {svc for svc, _ in services_with_off_profile(manifest)}
    try:
        validate_user_compose(
            paths.project_compose(name), paths,
            off_services=off_services,
            project_name=name,
            cve_policy=manifest.get("security"),
            manifest_services=manifest.get("services"),
            user_entries=manifest.get(USER_ENTRIES),
        )
    except ComposeSecurityError as e:
        return str(e)
    return None


def write_maintenance_page(paths: BoxPaths, name: str, manifest: dict[str, Any]) -> None:
    hosts = manifest.get("hosts", [])
    if not hosts:
        return
    try:
        atomic_write_text(paths.project_caddy_site(name),
                          render_maintenance_caddy_config(hosts), mode=0o644)
    except (OSError, ValueError) as e:
        raise UpgradeGateError(
            f"Failed to re-render the maintenance page for {name}: {e}") from e


def _compose_files(paths: BoxPaths, name: str) -> list[str]:
    compose_files = ["compose.yml"]
    if paths.project_compose_override(name).exists():
        compose_files.append("compose.boxmunge.yml")
    return compose_files


def _record_bind_sources(paths: BoxPaths, name: str) -> str | None:
    """Record the bind sources the project starts with, as deploy does;
    return why the start checks refused it, or None.

    The overlay this upgrade wrote may mount differently from the one the
    project was deployed with, and a project deployed before boxmunge
    recorded bind sources has no record; restart_projects and every later
    start check against this one. The check logs and alerts a refusal.
    """
    try:
        check_start(paths, name, component="upgrade",
                    compose_files=_compose_files(paths, name), record=True)
    except ComposeRefused as e:
        return str(e)
    return None


@dataclass
class Regeneration:
    """What the apply's regeneration did: projects whose live configs were
    rewritten, and projects refused by the compose validator (name -> why)."""
    processed: list[str] = field(default_factory=list)
    refused: dict[str, str] = field(default_factory=dict)


def _regenerate_project(
    paths: BoxPaths, name: str, manifest: dict[str, Any], regen: Regeneration,
) -> None:
    """Write one project's Caddy site config and compose overlay. Caller
    holds its project lock and has excluded it if it must be left alone."""
    # A paused or CVE-quarantined project is deliberately offline. Its Caddy
    # fragment must stay the maintenance page: regenerating live routing
    # would send visitors to stopped upstreams (502) instead of the page the
    # operator chose. Re-render the maintenance page (so a template change
    # still reaches it) and leave the overlay alone; resume and security
    # resume regenerate both when the project comes back.
    block = is_blocked(name, paths)
    if block:
        write_maintenance_page(paths, name, manifest)
        log_operation("upgrade", block.skip_message, paths, project=name)
        if not paths.project_bind_record(name).exists():
            _record_bind_sources(paths, name)
        return
    # A compose.yml that predates a validator fix must not get a fresh
    # overlay, nor be rebuilt and re-run as root by restart_projects. Its
    # old configs and running containers are left untouched; the upgrade
    # itself goes on, since rolling back would only restore the validator
    # that let the file in.
    refusal = compose_refusal(paths, name, manifest)
    if refusal is not None:
        regen.refused[name] = refusal
        log_error("upgrade", f"Compose validation refused {name}: {refusal}. Its "
                  f"configs and running containers are left as they were and it "
                  f"is not restarted; fix compose.yml and redeploy.",
                  paths, project=name)
        return
    try:
        prepare_caddy_config(paths, manifest)
        prepare_compose_override(paths, manifest, component="upgrade")
    except Exception as e:
        # The project would restart on its old overlay; fail so the shim
        # rolls back instead of reporting a half-applied upgrade (D-07).
        raise UpgradeGateError(f"Failed to regenerate configs for {name}: {e}") from e
    refusal = _record_bind_sources(paths, name)
    if refusal is not None:
        regen.refused[name] = refusal
        return
    regen.processed.append(name)


def _in_memory_line(name: str, written: object) -> str:
    if written is None:
        return (f"{name}: repository manifest.yml has no schema_version; the "
                f"upgrade will alert to set it to {CURRENT_SCHEMA_VERSION} in the "
                f"repository")
    return (f"{name}: repository manifest.yml uses schema v{written}; migrated in "
            f"memory to v{CURRENT_SCHEMA_VERSION} (the upgrade will alert to update "
            f"it in the repository)")


def _left_as_is_line(paths: BoxPaths, name: str) -> str | None:
    """The dry run's line for a project the apply will exclude, or None. Its
    files are neither rendered nor checked, so such a project can never fail
    the dry run."""
    why = exclusion(paths, name)
    if why is None:
        return None
    if isinstance(why, LegacyStage):
        return (f"{name}: a release staged by boxmunge 0.10.1 ({why.kind}) will be left "
                f"as is; after the upgrade, resolve it with boxmunge-server legacy-stage "
                f"{name}")
    if isinstance(why, InstallTxn):
        line = f"{name}: an install ({why.ref}, {why.phase}) is open; the project will be left as is"
        unreadable = _unreadable_release_files(paths, name, why)[1]
        return line if unreadable is None else f"{line} ({unreadable})"
    if isinstance(why, OSError):
        return f"{name}: the project will be left as is: {cannot_tell_left_as_is(name, why)}"
    return f"{name}: {why}; the project will be left as is"


def check_upgrade(paths: BoxPaths) -> list[str]:
    """Dry run of migrate + regenerate: everything is rendered in memory and
    nothing is written, locked or logged. Raises on anything that would make
    --apply fail. Returns one report line per project."""
    report = []
    for project_dir in _project_dirs(paths):
        name = project_dir.name
        left = _left_as_is_line(paths, name)
        if left is not None:
            report.append(left)
            continue
        manifest = load_manifest_as_written(require_manifest(project_dir))
        migrated = _migrated(project_dir, manifest)
        unlinked = unlinked_files(project_dir, manifest)
        if unlinked:
            report.append(f"WARNING {relink_advice(project_dir, unlinked)}")
        if migrated is not None:
            written = manifest.get("schema_version")
            if _links_into_repository(project_dir):
                report.append(_in_memory_line(name, written))
            else:
                report.append(f"{name}: migration OK (schema v{written or 1} "
                              f"-> v{CURRENT_SCHEMA_VERSION})")
            manifest = migrated
        manifest = split_user_entries(manifest)  # as loading does
        block = is_blocked(name, paths)
        if block:
            if manifest.get("hosts"):
                render_maintenance_caddy_config(manifest["hosts"])
            report.append(f"{name}: {block.reason.value}; keeps its maintenance page")
            continue
        refusal = compose_refusal(paths, name, manifest)
        if refusal is not None:
            report.append(f"{name}: would be refused by this release's compose "
                          f"validator and left on its current configs and "
                          f"containers, not restarted: {refusal}")
            continue
        if not paths.project_caddy_override(name).exists():
            generate_caddy_config(manifest)
        generate_compose_override(
            manifest, user_compose=load_user_compose(paths.project_compose(name), name),
        )
        report.append(f"{name}: configs render OK")
    return report


@dataclass
class Restart:
    """What restart_projects did with each project it did not leave offline
    on purpose (paused and quarantined projects are not listed)."""
    succeeded: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    skipped_locked: list[str] = field(default_factory=list)
    monitor_stopped: list[str] = field(default_factory=list)
    # Refused by the start checks (compose_guard), which alerted for each.
    start_refused: list[str] = field(default_factory=list)


def restart_projects(paths: BoxPaths, *, refused: Collection[str],
                     excluded: Collection[str] = ()) -> Restart:
    """Restart all deployed projects under per-project locks.

    Projects in `refused` (see _regenerate_project) are skipped: their old
    containers keep running untouched, never rebuilt from the refused file.
    So are those the apply left as they are (upgrade_exclusions); one whose
    install opened since is refused by the start checks.

    A project whose project_lock is held by another operation is skipped
    (logged as a warning), not retried and not raised — the v0.4
    concurrency contract is that all mutating compose ops hold
    project_lock; an upgrade that races a deploy must defer to the deploy.
    """
    result = Restart()
    for project_dir in _project_dirs(paths):
        project_name = project_dir.name
        if project_name in excluded:
            log_operation("upgrade", f"Not restarting {project_name}: the upgrade left it "
                          f"as it is", paths, project=project_name)
            continue
        try:
            with project_lock(project_name, paths):
                _restart_locked(paths, project_dir, project_name, refused, result)
        except LockError:
            result.skipped_locked.append(project_name)
            log_warning(
                "upgrade",
                f"Skipped restart of project {project_name} — held by another "
                f"operation; will be picked up on next deploy or container-update",
                paths, project=project_name,
            )

    return result


def _restart_locked(
    paths: BoxPaths, project_dir: Path, project_name: str,
    refused: Collection[str], result: Restart,
) -> None:
    """Restart one project, recording the outcome in `result`. Caller holds
    its project lock.

    Every reason to leave the project alone is checked here, under the
    lock: a pause or quarantine that completed while the upgrade waited for
    the lock must not be undone.
    """
    # Never restart a project that is intentionally not running.
    # Quarantined: bringing containers back would silently undo a
    # security action. Paused: same — operator deliberately offlined
    # the project. Quarantine specifically gets a structured log
    # entry so the operator sees the skip in the daily report;
    # paused historically did not log here, so preserve that.
    block = is_blocked(project_name, paths)
    if block:
        if block.reason is BlockReason.QUARANTINED:
            log_operation("upgrade", block.skip_message, paths, project=project_name)
        return
    # The health monitor stopped it after a critical result. Starting
    # it would leave the stop marker standing over a running project
    # (nothing bumps last_started_at here); `recover`, or a deploy,
    # brings it back deliberately.
    if is_monitor_stopped(project_name, paths):
        result.monitor_stopped.append(project_name)
        log_operation("upgrade", f"Not restarting {project_name}: the health "
                      f"monitor stopped it; run `recover {project_name}` once "
                      f"it is fixed", paths, project=project_name)
        return
    if project_name in refused:
        log_operation("upgrade", f"Not restarting {project_name}: its compose.yml "
                      f"was refused; its containers are left as they are",
                      paths, project=project_name)
        return

    try:
        compose_up_checked(paths, project_name, component="upgrade",
                           compose_files=_compose_files(paths, project_name))
        result.succeeded.append(project_name)
    except ComposeRefused:
        # Logged and alerted by the check (its files or mounts changed since
        # deploy). Not a failed upgrade: rolling back would only restore a
        # release without the check.
        result.start_refused.append(project_name)
    except DockerError as e:
        result.failed.append(project_name)
        log_error("upgrade", f"Failed to restart {project_name}: {e}",
                  paths, project=project_name)
