# SPDX-License-Identifier: Apache-2.0
"""boxmunge upgrade -- single command for platform updates.

Flow: stash -> migrate manifests -> regenerate configs -> reload Caddy ->
restart projects -> self-test -> health -> report.

Dispatch modes:
  --dry-run   validate manifests + config regeneration; no writes to state
  --apply     migrate/regen/reload/restart/version-write only (shim handles
              stash, health, rollback externally)
  (default)   full six-step flow with stash, self-test, and health check
"""

import sys
from typing import Any

import yaml

from boxmunge.commands.deploy import prepare_caddy_config, prepare_compose_override
from boxmunge.commands.health_cmd import run_health
from boxmunge.commands.self_test_cmd import run_self_test
from boxmunge.compose_validate import validate_user_compose, ComposeSecurityError
from boxmunge.docker import compose_up, caddy_reload, DockerError
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, validate_manifest, ManifestError, CURRENT_SCHEMA_VERSION
from boxmunge.migration import migrate_manifest, MigrationError
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import services_with_off_profile
from boxmunge.stash import create_stash, prune_stashes
from boxmunge.version import read_installed_version, write_installed_version, get_build_version, parse_version_string


def _migrate_project_manifests(paths: BoxPaths) -> list[str]:
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

        from boxmunge.fileutil import atomic_write_text
        atomic_write_text(
            manifest_path,
            yaml.dump(migrated_manifest, default_flow_style=False, sort_keys=False),
        )
        migrated.append(project_dir.name)

    return migrated


def _regenerate_configs(paths: BoxPaths) -> list[str]:
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
        # Validate user compose.yml against silent-floor-defeating keys
        # BEFORE regenerating the overlay. A hostile compose.yml that
        # slipped in pre-validation must not survive an upgrade.
        off_services = {svc for svc, _ in services_with_off_profile(manifest)}
        try:
            validate_user_compose(
                paths.project_compose(project_name), off_services=off_services,
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


def _restart_projects(paths: BoxPaths) -> tuple[list[str], list[str]]:
    """Restart all deployed projects. Returns (succeeded, failed) lists."""
    succeeded = []
    failed = []
    if not paths.projects.exists():
        return succeeded, failed

    for project_dir in sorted(paths.projects.iterdir()):
        if not project_dir.is_dir():
            continue
        manifest_path = project_dir / "manifest.yml"
        if not manifest_path.exists():
            continue

        project_name = project_dir.name
        compose_files = ["compose.yml"]
        override = paths.project_compose_override(project_name)
        if override.exists():
            compose_files.append("compose.boxmunge.yml")

        try:
            compose_up(project_dir, compose_files=compose_files)
            succeeded.append(project_name)
        except DockerError as e:
            failed.append(project_name)
            log_error(
                "upgrade", f"Failed to restart {project_name}: {e}",
                paths, project=project_name,
            )

    return succeeded, failed


def _run_dry(paths: BoxPaths) -> int:
    """Validate manifest migrations and config regeneration without touching state.

    Config files (Caddy/compose) are generated files; writing them here is safe
    because the real upgrade will regenerate them anyway.
    Returns 0 if no exceptions, 1 on error.
    """
    print("boxmunge upgrade --dry-run")
    print("==========================\n")

    print("[1/2] Validating manifest migrations...")
    if paths.projects.exists():
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
            source_version = manifest.get("schema_version", 1)
            if source_version == CURRENT_SCHEMA_VERSION:
                print(f"  {project_dir.name}: up to date")
                continue
            try:
                migrate_manifest(manifest, CURRENT_SCHEMA_VERSION)
                print(f"  {project_dir.name}: migration OK (schema v{source_version} -> v{CURRENT_SCHEMA_VERSION})")
            except MigrationError as e:
                print(f"  {project_dir.name}: ERROR: {e}")
                return 1
    print("  OK")

    print("[2/2] Validating config regeneration...")
    try:
        _regenerate_configs(paths)
        print("  OK")
    except Exception as e:
        print(f"  ERROR: {e}")
        return 1

    print("\nDry-run complete. No state was modified.")
    return 0


def _run_apply(paths: BoxPaths, current_version: str, new_version: str) -> int:
    """Run migrate/regen/reload/restart/version-write only.

    The upgrade shim handles stash creation, health checks, and rollback
    externally, so we skip those here.
    Returns 0 on success, 1 if any project failed to restart.
    """
    print("boxmunge upgrade --apply")
    print("========================\n")
    print(f"  Current: {current_version}")
    print(f"  New:     {new_version}\n")

    # Step 1: Migrate manifests
    print("[1/4] Migrating manifests...")
    migrated = _migrate_project_manifests(paths)
    if migrated:
        print(f"  Migrated: {', '.join(migrated)}")
    else:
        print("  No migrations needed.")

    # Step 2: Regenerate configs
    print("[2/4] Regenerating configs...")
    processed = _regenerate_configs(paths)
    print(f"  Processed: {len(processed)} project(s)")

    # Step 3: Reload Caddy
    print("[3/4] Reloading Caddy...")
    try:
        caddy_reload(paths.caddy)
        print("  Caddy reloaded.")
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    # Step 4: Restart projects
    print("[4/4] Restarting projects...")
    succeeded, failed_projects = _restart_projects(paths)
    if succeeded:
        print(f"  Restarted: {', '.join(succeeded)}")
    if failed_projects:
        print(f"  FAILED: {', '.join(failed_projects)}")

    # Write version
    semver, commit = parse_version_string(new_version)
    write_installed_version(paths, semver, commit)

    log_operation(
        "upgrade", f"Apply {current_version} -> {new_version}", paths,
        detail={"migrated": migrated, "restarted": succeeded, "failed": failed_projects},
    )

    if failed_projects:
        return 1
    return 0


def _run_full(
    paths: BoxPaths,
    current_version: str,
    new_version: str,
    skip_self_test: bool,
) -> int:
    """Run the complete six-step upgrade flow."""
    # Step 1: Stash
    print("[1/6] Creating stash...")
    try:
        archive = create_stash(paths)
        print(f"  Stash: {archive.name}")
    except Exception as e:
        print(f"  ERROR: Stash failed: {e}")
        log_error("upgrade", f"Stash failed: {e}", paths)
        return 1

    # Step 2: Migrate manifests
    print("[2/6] Migrating manifests...")
    migrated = _migrate_project_manifests(paths)
    if migrated:
        print(f"  Migrated: {', '.join(migrated)}")
    else:
        print("  No migrations needed.")

    # Step 3: Regenerate configs
    print("[3/6] Regenerating configs...")
    processed = _regenerate_configs(paths)
    print(f"  Processed: {len(processed)} project(s)")

    # Step 4: Reload Caddy
    print("[4/6] Reloading Caddy...")
    try:
        caddy_reload(paths.caddy)
        print("  Caddy reloaded.")
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    # Step 5: Restart projects
    print("[5/6] Restarting projects...")
    succeeded, failed_projects = _restart_projects(paths)
    if succeeded:
        print(f"  Restarted: {', '.join(succeeded)}")
    if failed_projects:
        print(f"  FAILED: {', '.join(failed_projects)}")

    # Prune old stashes
    prune_stashes(paths, keep=5)

    # Post-upgrade validation
    print("\n[Post-upgrade validation]")

    if not skip_self_test:
        print("\nRunning self-test...")
        self_test_result = run_self_test(paths)
        if self_test_result != 0:
            print("  WARN: Self-test failed (platform may still be functional)")
    else:
        print("  Self-test skipped.")

    print("\nRunning health check...")
    health_result = run_health(paths)

    if health_result == 2:
        print("  Health check found issues requiring attention.")
        return 1

    # Only write version after health check passes
    semver, commit = parse_version_string(new_version)
    write_installed_version(paths, semver, commit)

    print(f"\nUpgrade complete: {current_version} -> {new_version}")

    log_operation(
        "upgrade", f"Upgrade {current_version} -> {new_version}", paths,
        detail={"migrated": migrated, "restarted": succeeded, "failed": failed_projects},
    )

    if failed_projects:
        return 1
    return 0


def run_upgrade(
    paths: BoxPaths,
    skip_self_test: bool = False,
    *,
    dry_run: bool = False,
    apply_only: bool = False,
) -> int:
    """Dispatch upgrade to the appropriate mode. Returns 0 on success."""
    if dry_run:
        return _run_dry(paths)

    print("boxmunge upgrade")
    print("================\n")

    current_version = read_installed_version(paths)
    new_version = get_build_version()
    print(f"  Current: {current_version}")
    print(f"  New:     {new_version}\n")

    if apply_only:
        return _run_apply(paths, current_version, new_version)

    return _run_full(paths, current_version, new_version, skip_self_test)


UPGRADE_USAGE = """\
Usage: boxmunge upgrade [--dry-run | --apply] [--skip-self-test]

Manual upgrade entry point. From the deploy shell, `upgrade` (no args) is
routed through the root-context bash shim which handles stash + venv swap +
probation. The flags below are for the shim and direct invocations only.

Flags:
  --dry-run         Validate manifest migrations and config regeneration
                    without modifying state. Used for pre-flight checks.
  --apply           Migrate/regen/reload/restart only. The shim calls this
                    after creating its own stash; do not use directly.
  --skip-self-test  Skip the post-upgrade self-test step.
  -h, --help        Show this message.
"""


def cmd_upgrade(args: list[str]) -> None:
    """CLI entry point for upgrade command."""
    if "-h" in args or "--help" in args:
        print(UPGRADE_USAGE)
        sys.exit(0)

    known = {"--skip-self-test", "--dry-run", "--apply"}
    unknown = [a for a in args if a not in known]
    if unknown:
        print(f"ERROR: unknown argument(s): {' '.join(unknown)}", file=sys.stderr)
        print(UPGRADE_USAGE, file=sys.stderr)
        sys.exit(2)

    skip_self_test = "--skip-self-test" in args
    dry_run = "--dry-run" in args
    apply_only = "--apply" in args
    if dry_run and apply_only:
        print("ERROR: --dry-run and --apply are mutually exclusive", file=sys.stderr)
        sys.exit(2)

    paths = BoxPaths()
    sys.exit(run_upgrade(paths, skip_self_test, dry_run=dry_run, apply_only=apply_only))
