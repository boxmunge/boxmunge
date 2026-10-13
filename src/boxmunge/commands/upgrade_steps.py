# SPDX-License-Identifier: Apache-2.0
"""Per-project steps of a platform upgrade.

migrate manifests -> regenerate configs -> (Caddy reload) -> restart projects.
upgrade_cmd sequences these for --dry-run, --apply and the full flow.
"""

import yaml

from boxmunge.caddy import prepare_caddy_config
from boxmunge.compose import prepare_compose_override
from boxmunge.compose_validate import validate_user_compose, ComposeSecurityError
from boxmunge.docker import compose_up, DockerError
from boxmunge.fileutil import atomic_write_text, project_lock, LockError
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, validate_manifest, ManifestError, CURRENT_SCHEMA_VERSION
from boxmunge.migration import migrate_manifest, MigrationError
from boxmunge.pause import render_maintenance_caddy_config
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import services_with_off_profile


def migrate_project_manifests(paths: BoxPaths) -> list[str]:
    """Migrate all project manifests to the current schema version.

    Returns list of project names that were migrated.
    """
    migrated = []
    if not paths.projects.exists():
        return migrated

    for project_dir in sorted(paths.projects.iterdir()):
        if not project_dir.is_dir():
            continue
        manifest_path = project_dir / "manifest.yml"
        if not manifest_path.exists():
            continue

        # ManifestError and MigrationError both propagate. A corrupted manifest
        # means this project never gets its schema bumped or overlay regenerated;
        # silently skipping would let the upgrade report success while leaving
        # the project in a stale/broken state. Raise instead — the shim will
        # roll back to the previous slot.
        manifest = load_manifest(manifest_path)

        source_version = manifest.get("schema_version", 1)
        if source_version == CURRENT_SCHEMA_VERSION:
            continue

        migrated_manifest = migrate_manifest(manifest, CURRENT_SCHEMA_VERSION)

        # Validate the migrated manifest BEFORE writing it.
        # A migration that produces invalid output is a real bug — fail noisily
        # rather than persisting a malformed manifest the operator will hit
        # later at deploy time.
        errors, _ = validate_manifest(migrated_manifest, expected_name=project_dir.name)
        if errors:
            log_error(
                "upgrade",
                f"Migrated manifest for {project_dir.name} failed validation: "
                f"{'; '.join(errors)}. Original manifest left in place.",
                paths, project=project_dir.name,
            )
            raise MigrationError(
                f"Migrated manifest for {project_dir.name} failed validation. "
                f"Errors: {'; '.join(errors)}"
            )

        atomic_write_text(
            manifest_path,
            yaml.dump(migrated_manifest, default_flow_style=False, sort_keys=False),
        )
        migrated.append(project_dir.name)

    return migrated


def regenerate_configs(paths: BoxPaths) -> list[str]:
    """Re-generate Caddy and compose overlay configs for all projects.

    Returns list of project names processed.
    """
    processed = []
    if not paths.projects.exists():
        return processed

    for project_dir in sorted(paths.projects.iterdir()):
        if not project_dir.is_dir():
            continue
        manifest_path = project_dir / "manifest.yml"
        if not manifest_path.exists():
            continue

        try:
            manifest = load_manifest(manifest_path)
        except ManifestError:
            continue

        project_name = manifest.get("project", project_dir.name)

        # A CVE-quarantined project must NOT have its normal Caddy
        # site fragment overwritten by a platform upgrade — that would
        # silently restore routing to a stopped (or about-to-be-restored)
        # project the operator deliberately took offline. Re-render the
        # maintenance fragment instead so the quarantine UX persists
        # through the upgrade. Compose overlay regen is skipped — the
        # containers stay stopped until `boxmunge security resume`.
        # Pause is intentionally NOT short-circuited here: historical
        # behavior is to regenerate normal configs for paused projects
        # too. Pause's own Caddy fragment is written on resume.
        block = is_blocked(project_name, paths)
        if block and block.reason is BlockReason.QUARANTINED:
            hosts = manifest.get("hosts", [])
            if hosts:
                try:
                    site_conf = render_maintenance_caddy_config(hosts)
                    paths.project_caddy_site(project_name).parent.mkdir(
                        parents=True, exist_ok=True,
                    )
                    atomic_write_text(
                        paths.project_caddy_site(project_name),
                        site_conf, mode=0o644,
                    )
                except (OSError, ValueError) as e:
                    log_warning(
                        "upgrade",
                        f"Failed to re-render maintenance Caddy config "
                        f"for quarantined {project_name}: {e}",
                        paths, project=project_name,
                    )
            log_operation(
                "upgrade", block.skip_message,
                paths, project=project_name,
            )
            continue

        # Validate user compose.yml against silent-floor-defeating keys
        # BEFORE regenerating the overlay. A hostile compose.yml that
        # slipped in pre-validation must not survive an upgrade.
        off_services = {svc for svc, _ in services_with_off_profile(manifest)}
        try:
            validate_user_compose(
                paths.project_compose(project_name), paths,
                off_services=off_services,
                project_name=project_name,
                cve_policy=manifest.get("security"),
                manifest_services=manifest.get("services"),
            )
        except ComposeSecurityError as e:
            log_error(
                "upgrade",
                f"Compose validation rejected during regen: {e}",
                paths, project=project_name,
            )
            # Skip this project's regen — leave its existing configs in
            # place. Upgrade should not silently produce a fresh overlay
            # over a hostile user compose.yml.
            continue
        try:
            prepare_caddy_config(paths, manifest)
            prepare_compose_override(paths, manifest, component="upgrade")
            processed.append(project_name)
        except Exception as e:
            log_warning(
                "upgrade", f"Failed to regenerate configs for {project_name}: {e}",
                paths, project=project_name,
            )

    return processed


def notify_locked_skips(paths: BoxPaths, skipped_locked: list[str]) -> None:
    """Send a Pushover summary when restart_projects skipped any projects.

    The lock-skip is logged but, in non-interactive contexts (cron timer,
    auto-update path), the operator never sees the warning. This raises
    the visibility to the same channel as other upgrade-time alerts.
    Pushover failures degrade gracefully to log_error — same I-2b pattern
    as container_update_cmd._send_summary_alert.
    """
    if not skipped_locked:
        return
    title = "boxmunge upgrade — projects skipped restart"
    names = ", ".join(skipped_locked)
    body = (
        f"Upgrade applied but {len(skipped_locked)} project(s) skipped "
        f"restart (locked): {names}. They will pick up new config on next "
        f"deploy."
    )
    try:
        from boxmunge.config import load_config
        from boxmunge.pushover import send_notification
        cfg = load_config(paths)
        po = cfg.get("pushover", {})
        send_notification(
            po.get("user_key", ""), po.get("app_token", ""),
            title, body,
        )
    except Exception as e:
        log_error(
            "upgrade", f"Pushover lock-skip alert failed: {e}", paths,
            detail={"skipped_locked": skipped_locked},
        )


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
        if not manifest_path.exists():
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
                    compose_up(project_dir, compose_files=compose_files)
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
