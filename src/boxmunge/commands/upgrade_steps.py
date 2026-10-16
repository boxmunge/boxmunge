# SPDX-License-Identifier: Apache-2.0
"""Per-project steps of a platform upgrade.

migrate manifests -> regenerate configs -> (Caddy reload) -> restart projects.
upgrade_cmd sequences these for --apply and the full flow; check_upgrade is
the write-nothing rendering behind --dry-run.
"""

from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from boxmunge.caddy import generate_caddy_config, prepare_caddy_config
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.compose import generate_compose_override, load_user_compose, prepare_compose_override
from boxmunge.compose_validate import validate_user_compose, ComposeSecurityError
from boxmunge.compose_guard import ComposeRefused, check_start, compose_up_checked
from boxmunge.release_staging import has_prestage
from boxmunge.docker import DockerError
from boxmunge.fileutil import atomic_write_text, project_lock, LockError
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import (
    CURRENT_SCHEMA_VERSION, load_manifest, load_manifest_as_written, validate_manifest,
    write_manifest,
)
from boxmunge.git_layout import alert_old_schema, alert_unlinked, relink_advice, unlinked_files
from boxmunge.migration import migrate_manifest, MigrationError
from boxmunge.pause import render_maintenance_caddy_config
from boxmunge.fleet import report_project_failure
from boxmunge.paths import BoxPaths, InvalidProjectName, validate_project_name
from boxmunge.security_overlay import services_with_off_profile


class UpgradeGateError(Exception):
    """A step the upgrade cannot succeed without failed; the shim rolls back."""


def _project_manifests(
    paths: BoxPaths, load: Callable[[Path], dict[str, Any]],
) -> Iterator[tuple[Path, dict[str, Any]]]:
    """Yield (project_dir, load(manifest.yml)) for every project that has a
    manifest: load_manifest_as_written to migrate it, load_manifest to use it.

    ManifestError propagates. A corrupted manifest means the project never
    gets its schema bumped or overlay regenerated; skipping it would let the
    upgrade report success over a stale project. The shim rolls back instead.
    """
    if not paths.projects.exists():
        return
    for project_dir in sorted(paths.projects.iterdir()):
        manifest_path = project_dir / "manifest.yml"
        if project_dir.is_dir() and manifest_path.exists() and _addressable(project_dir, paths):
            yield project_dir, load(manifest_path)


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
    links into the repository and is migrated by every reader instead;
    `skipped_locked` were held by another operation and are migrated in
    memory until the next upgrade. `unlinked` maps each git project whose
    manifest.yml or compose.yml is not a link into repo/ to the fix."""
    written: list[str] = field(default_factory=list)
    in_memory: list[str] = field(default_factory=list)
    skipped_locked: list[str] = field(default_factory=list)
    unlinked: dict[str, str] = field(default_factory=dict)


def _links_into_repository(project_dir: Path) -> bool:
    return (project_dir / "manifest.yml").is_symlink()


def migrate_project_manifests(paths: BoxPaths) -> ManifestMigration:
    """Migrate all project manifests to the current schema version.

    A git project's manifest.yml is never written: replacing its link with
    a file would detach the project from its repository's manifest. Its
    operator is alerted, once, to update the file in the repository, and
    once about a git project whose links an older upgrade replaced.

    Each write is under the project lock. A project whose lock is held is
    left at its schema on disk: every reader migrates it in memory, and the
    next upgrade writes it.
    """
    result = ManifestMigration()
    for project_dir, manifest in _project_manifests(paths, load_manifest_as_written):
        name = project_dir.name
        unlinked = alert_unlinked(paths, project_dir, manifest)
        if unlinked:
            result.unlinked[name] = relink_advice(project_dir, unlinked)
        try:
            migrated = _migrated(project_dir, manifest)
        except MigrationError as e:
            log_error("upgrade", f"{e}. Original manifest left in place.",
                      paths, project=name)
            raise
        if migrated is None:
            continue
        if _links_into_repository(project_dir):
            alert_old_schema(paths, name, manifest.get("schema_version"))
            result.in_memory.append(name)
            continue
        try:
            with project_lock(name, paths):
                write_manifest(project_dir / "manifest.yml", migrated)
        except LockError:
            result.skipped_locked.append(name)
            log_warning("upgrade", f"Manifest of {name} not migrated on disk: held "
                        f"by another operation. It is migrated in memory until the "
                        f"next upgrade", paths, project=name)
            continue
        result.written.append(name)
    return result


def _compose_refusal(paths: BoxPaths, name: str, manifest: dict[str, Any]) -> str | None:
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
        )
    except ComposeSecurityError as e:
        return str(e)
    return None


def _write_maintenance_site(paths: BoxPaths, name: str, manifest: dict[str, Any]) -> None:
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
    While a release is staged the project directory holds the staged
    release's files, so there is nothing of production's to record;
    restart_projects refuses the project.
    """
    if has_prestage(paths, name):
        return None
    try:
        check_start(paths, name, component="upgrade",
                    compose_files=_compose_files(paths, name), record=True)
    except ComposeRefused as e:
        return str(e)
    return None


@dataclass
class Regeneration:
    """What regenerate_configs did: projects whose live configs were
    rewritten, and projects refused by the compose validator (name -> why)."""
    processed: list[str] = field(default_factory=list)
    refused: dict[str, str] = field(default_factory=dict)


def _regenerate_project(
    paths: BoxPaths, name: str, manifest: dict[str, Any], regen: Regeneration,
) -> None:
    """Write one project's Caddy site config and compose overlay."""
    # A paused or CVE-quarantined project is deliberately offline. Its Caddy
    # fragment must stay the maintenance page: regenerating live routing
    # would send visitors to stopped upstreams (502) instead of the page the
    # operator chose. Re-render the maintenance page (so a template change
    # still reaches it) and leave the overlay alone; resume and security
    # resume regenerate both when the project comes back.
    block = is_blocked(name, paths)
    if block:
        _write_maintenance_site(paths, name, manifest)
        log_operation("upgrade", block.skip_message, paths, project=name)
        if not paths.project_bind_record(name).exists():
            _record_bind_sources(paths, name)
        return
    # A compose.yml that predates a validator fix must not get a fresh
    # overlay, nor be rebuilt and re-run as root by restart_projects. Its
    # old configs and running containers are left untouched; the upgrade
    # itself goes on, since rolling back would only restore the validator
    # that let the file in.
    refusal = _compose_refusal(paths, name, manifest)
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


def regenerate_configs(paths: BoxPaths) -> Regeneration:
    """Re-generate Caddy and compose overlay configs for all projects, each
    under its project lock. A project whose lock is held is left alone: the
    operation holding it (a deploy, say) writes its own configs.
    """
    regen = Regeneration()
    for project_dir, manifest in _project_manifests(paths, load_manifest):
        name = manifest.get("project", project_dir.name)
        try:
            with project_lock(name, paths):
                _regenerate_project(paths, name, manifest, regen)
        except LockError:
            log_warning(
                "upgrade",
                f"Skipped config regeneration for {name} — held by another "
                f"operation, which writes its own configs",
                paths, project=name,
            )
    return regen


def _in_memory_line(name: str, written: object) -> str:
    if written is None:
        return (f"{name}: repository manifest.yml has no schema_version; the "
                f"upgrade will alert to set it to {CURRENT_SCHEMA_VERSION} in the "
                f"repository")
    return (f"{name}: repository manifest.yml uses schema v{written}; migrated in "
            f"memory to v{CURRENT_SCHEMA_VERSION} (the upgrade will alert to update "
            f"it in the repository)")


def check_upgrade(paths: BoxPaths) -> list[str]:
    """Dry run of migrate + regenerate: everything is rendered in memory and
    nothing is written, locked or logged. Raises on anything that would make
    --apply fail. Returns one report line per project."""
    report = []
    for project_dir, manifest in _project_manifests(paths, load_manifest_as_written):
        name = manifest.get("project", project_dir.name)
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
        block = is_blocked(name, paths)
        if block:
            if manifest.get("hosts"):
                render_maintenance_caddy_config(manifest["hosts"])
            report.append(f"{name}: {block.reason.value}; keeps its maintenance page")
            continue
        refusal = _compose_refusal(paths, name, manifest)
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


def notify_locked_skips(paths: BoxPaths, skipped_locked: list[str]) -> None:
    """Send a Pushover summary when restart_projects skipped any projects.

    The lock-skip is logged but, in non-interactive contexts (cron timer,
    auto-update path), the operator never sees the warning. This raises
    the visibility to the same channel as other upgrade-time alerts;
    ``notify`` logs a non-delivery.
    """
    if not skipped_locked:
        return
    from boxmunge.notify import notify
    names = ", ".join(skipped_locked)
    notify(paths, "upgrade — projects skipped restart",
           f"Upgrade applied but {len(skipped_locked)} project(s) skipped "
           f"restart (locked): {names}. They will pick up new config on next "
           f"deploy.", component="upgrade")


def notify_refused(paths: BoxPaths, refused: dict[str, str]) -> None:
    """One priority-1 alert per upgrade naming every refused project.

    One summary rather than one alert per project; the dry run never
    alerts, so an upgrade alerts once, and again on a later upgrade only
    while the compose.yml is still refused.
    """
    if not refused:
        return
    from boxmunge.notify import notify
    lines = "\n".join(f"- {name}: {why}" for name, why in sorted(refused.items()))
    notify(paths, "upgrade — compose refused",
           f"The upgrade's compose validator refused {len(refused)} project(s). "
           f"They keep their previous configs and running containers and were "
           f"not restarted. Fix compose.yml and redeploy:\n{lines}",
           component="upgrade", priority=1)


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


def restart_projects(paths: BoxPaths, *, refused: Collection[str]) -> Restart:
    """Restart all deployed projects under per-project locks.

    Projects in `refused` (see regenerate_configs) are skipped: their old
    containers keep running untouched, never rebuilt from the refused file.

    A project whose project_lock is held by another operation is skipped
    (logged as a warning), not retried and not raised — the v0.4
    concurrency contract is that all mutating compose ops hold
    project_lock; an upgrade that races a deploy must defer to the deploy.
    """
    result = Restart()
    if not paths.projects.exists():
        return result

    for project_dir in sorted(paths.projects.iterdir()):
        if not project_dir.is_dir():
            continue
        manifest_path = project_dir / "manifest.yml"
        if not manifest_path.exists() or not _addressable(project_dir, paths):
            continue

        project_name = project_dir.name
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
