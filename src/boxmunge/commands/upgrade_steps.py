# SPDX-License-Identifier: Apache-2.0
"""Per-project steps of a platform upgrade.

migrate manifests -> regenerate configs -> (Caddy reload) -> restart projects.
upgrade_cmd sequences these for --apply and the full flow; check_upgrade is
the write-nothing rendering behind --dry-run.
"""

from pathlib import Path
from typing import Any, Iterator

import yaml

from boxmunge.caddy import generate_caddy_config, prepare_caddy_config
from boxmunge.compose import generate_compose_override, load_user_compose, prepare_compose_override
from boxmunge.compose_validate import validate_user_compose, ComposeSecurityError
from boxmunge.docker import compose_up, DockerError
from boxmunge.fileutil import atomic_write_text, project_lock, LockError
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, validate_manifest, CURRENT_SCHEMA_VERSION
from boxmunge.migration import migrate_manifest, MigrationError
from boxmunge.pause import render_maintenance_caddy_config
from boxmunge.fleet import report_project_failure
from boxmunge.paths import BoxPaths, InvalidProjectName, validate_project_name
from boxmunge.security_overlay import services_with_off_profile


class UpgradeGateError(Exception):
    """A step the upgrade cannot succeed without failed; the shim rolls back."""


def _project_manifests(paths: BoxPaths) -> Iterator[tuple[Path, dict[str, Any]]]:
    """Yield (project_dir, manifest) for every project that has a manifest.

    ManifestError propagates. A corrupted manifest means the project never
    gets its schema bumped or overlay regenerated; skipping it would let the
    upgrade report success over a stale project. The shim rolls back instead.
    """
    if not paths.projects.exists():
        return
    for project_dir in sorted(paths.projects.iterdir()):
        manifest_path = project_dir / "manifest.yml"
        if project_dir.is_dir() and manifest_path.exists() and _addressable(project_dir, paths):
            yield project_dir, load_manifest(manifest_path)


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


def migrate_project_manifests(paths: BoxPaths) -> list[str]:
    """Migrate all project manifests to the current schema version.

    Returns list of project names that were migrated.
    """
    migrated_names = []
    for project_dir, manifest in _project_manifests(paths):
        try:
            migrated = _migrated(project_dir, manifest)
        except MigrationError as e:
            log_error("upgrade", f"{e}. Original manifest left in place.",
                      paths, project=project_dir.name)
            raise
        if migrated is None:
            continue
        atomic_write_text(
            project_dir / "manifest.yml",
            yaml.dump(migrated, default_flow_style=False, sort_keys=False),
        )
        migrated_names.append(project_dir.name)
    return migrated_names


def _compose_accepted(paths: BoxPaths, name: str, manifest: dict[str, Any]) -> bool:
    """Validate the user compose.yml against silent-floor-defeating keys.

    A hostile compose.yml that slipped in before validation must not get a
    fresh overlay from an upgrade; the project keeps its existing configs.
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
        log_error("upgrade", f"Compose validation rejected during regen: {e}",
                  paths, project=name)
        return False
    return True


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


def _regenerate_project(paths: BoxPaths, name: str, manifest: dict[str, Any]) -> bool:
    """Write one project's Caddy site config and compose overlay. Returns
    True if live configs were regenerated."""
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
        return False
    if not _compose_accepted(paths, name, manifest):
        return False
    try:
        prepare_caddy_config(paths, manifest)
        prepare_compose_override(paths, manifest, component="upgrade")
    except Exception as e:
        # The project would restart on its old overlay; fail so the shim
        # rolls back instead of reporting a half-applied upgrade (D-07).
        raise UpgradeGateError(f"Failed to regenerate configs for {name}: {e}") from e
    return True


def regenerate_configs(paths: BoxPaths) -> list[str]:
    """Re-generate Caddy and compose overlay configs for all projects, each
    under its project lock. A project whose lock is held is left alone: the
    operation holding it (a deploy, say) writes its own configs.

    Returns list of project names whose live configs were regenerated.
    """
    processed = []
    for project_dir, manifest in _project_manifests(paths):
        name = manifest.get("project", project_dir.name)
        try:
            with project_lock(name, paths):
                if _regenerate_project(paths, name, manifest):
                    processed.append(name)
        except LockError:
            log_warning(
                "upgrade",
                f"Skipped config regeneration for {name} — held by another "
                f"operation, which writes its own configs",
                paths, project=name,
            )
    return processed


def check_upgrade(paths: BoxPaths) -> list[str]:
    """Dry run of migrate + regenerate: everything is rendered in memory and
    nothing is written, locked or logged. Raises on anything that would make
    --apply fail. Returns one report line per project."""
    report = []
    for project_dir, manifest in _project_manifests(paths):
        name = manifest.get("project", project_dir.name)
        migrated = _migrated(project_dir, manifest)
        if migrated is not None:
            report.append(f"{name}: migration OK (schema v{manifest.get('schema_version', 1)} "
                          f"-> v{CURRENT_SCHEMA_VERSION})")
            manifest = migrated
        block = is_blocked(name, paths)
        if block:
            if manifest.get("hosts"):
                render_maintenance_caddy_config(manifest["hosts"])
            report.append(f"{name}: {block.reason.value}; keeps its maintenance page")
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


def restart_projects(
    paths: BoxPaths,
) -> tuple[list[str], list[str], list[str]]:
    """Restart all deployed projects under per-project locks.

    Returns (succeeded, failed, skipped_locked) lists. A project whose
    project_lock is held by another operation is skipped (logged as a
    warning), not retried and not raised — the v0.4 concurrency contract
    is that all mutating compose ops hold project_lock; an upgrade that
    races a deploy must defer to the deploy.
    """
    succeeded: list[str] = []
    failed: list[str] = []
    skipped_locked: list[str] = []
    if not paths.projects.exists():
        return succeeded, failed, skipped_locked

    for project_dir in sorted(paths.projects.iterdir()):
        if not project_dir.is_dir():
            continue
        manifest_path = project_dir / "manifest.yml"
        if not manifest_path.exists() or not _addressable(project_dir, paths):
            continue

        project_name = project_dir.name

        # Never restart a project that is intentionally not running.
        # Quarantined: bringing containers back would silently undo a
        # security action. Paused: same — operator deliberately offlined
        # the project. Quarantine specifically gets a structured log
        # entry so the operator sees the skip in the daily report;
        # paused historically did not log here, so preserve that.
        block = is_blocked(project_name, paths)
        if block:
            if block.reason is BlockReason.QUARANTINED:
                log_operation(
                    "upgrade", block.skip_message,
                    paths, project=project_name,
                )
            continue

        compose_files = ["compose.yml"]
        override = paths.project_compose_override(project_name)
        if override.exists():
            compose_files.append("compose.boxmunge.yml")

        try:
            with project_lock(project_name, paths):
                try:
                    compose_up(project_dir, compose_files=compose_files,
                               project_name=project_name)
                    succeeded.append(project_name)
                except DockerError as e:
                    failed.append(project_name)
                    log_error(
                        "upgrade", f"Failed to restart {project_name}: {e}",
                        paths, project=project_name,
                    )
        except LockError:
            skipped_locked.append(project_name)
            log_warning(
                "upgrade",
                f"Skipped restart of project {project_name} — held by another "
                f"operation; will be picked up on next deploy or container-update",
                paths, project=project_name,
            )

    return succeeded, failed, skipped_locked
