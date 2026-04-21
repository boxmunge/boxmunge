# SPDX-License-Identifier: Apache-2.0
"""boxmunge upgrade -- single command for platform updates.

Flow: stash -> migrate manifests -> regenerate configs -> reload Caddy ->
restart projects -> self-test -> health -> report.
"""

import sys
from typing import Any

import yaml

from boxmunge.commands.deploy import prepare_caddy_config, prepare_compose_override
from boxmunge.commands.health_cmd import run_health
from boxmunge.commands.self_test_cmd import run_self_test
from boxmunge.docker import compose_up, caddy_reload, DockerError
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, ManifestError, CURRENT_SCHEMA_VERSION
from boxmunge.migration import migrate_manifest, MigrationError
from boxmunge.paths import BoxPaths
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

        try:
            manifest = load_manifest(manifest_path)
        except ManifestError:
            continue

        source_version = manifest.get("schema_version", 1)
        if source_version == CURRENT_SCHEMA_VERSION:
            continue

        try:
            migrated_manifest = migrate_manifest(manifest, CURRENT_SCHEMA_VERSION)
            from boxmunge.fileutil import atomic_write_text
            atomic_write_text(
                manifest_path,
                yaml.dump(migrated_manifest, default_flow_style=False, sort_keys=False),
            )
            migrated.append(project_dir.name)
        except MigrationError as e:
            log_error(
                "upgrade", f"Failed to migrate {project_dir.name}: {e}",
                paths, project=project_dir.name,
            )

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
        try:
            prepare_caddy_config(paths, manifest)
            prepare_compose_override(paths, manifest)
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


def run_upgrade(paths: BoxPaths, skip_self_test: bool = False) -> int:
    """Run the full upgrade flow. Returns 0 on success."""
    print("boxmunge upgrade")
    print("================\n")

    current_version = read_installed_version(paths)
    new_version = get_build_version()
    print(f"  Current: {current_version}")
    print(f"  New:     {new_version}\n")

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


def cmd_upgrade(args: list[str]) -> None:
    """CLI entry point for upgrade command."""
    skip_self_test = "--skip-self-test" in args
    paths = BoxPaths()
    sys.exit(run_upgrade(paths, skip_self_test=skip_self_test))
