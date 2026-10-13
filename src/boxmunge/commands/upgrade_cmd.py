# SPDX-License-Identifier: Apache-2.0
"""boxmunge upgrade -- single command for platform updates.

Flow: stash -> migrate manifests -> regenerate configs -> reload Caddy ->
restart projects -> self-test -> health -> report.

Dispatch modes:
  --dry-run   render migrated manifests + configs in memory; writes nothing
  --apply     migrate/regen/reload/restart/version-write only (shim handles
              stash, health, rollback externally)
  (default)   full six-step flow with stash, self-test, and health check
"""

import sys

from boxmunge.commands.health_cmd import run_health
from boxmunge.commands.self_test_cmd import run_self_test
from boxmunge.commands.upgrade_steps import (
    check_upgrade,
    migrate_project_manifests,
    notify_locked_skips,
    regenerate_configs,
    restart_projects,
)
from boxmunge.docker import caddy_reload, DockerError
from boxmunge.log import log_operation, log_error
from boxmunge.paths import BoxPaths
from boxmunge.stash import create_stash, prune_stashes
from boxmunge.version import read_installed_version, write_installed_version, get_build_version, parse_version_string


def _run_dry(paths: BoxPaths) -> int:
    """Pre-flight for the shim: render every project's migrated manifest and
    configs in memory. Writes, locks and logs nothing. Returns 0 if --apply
    would get through migration and regeneration, 1 otherwise."""
    print("boxmunge upgrade --dry-run")
    print("==========================\n")
    try:
        report = check_upgrade(paths)
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        return 1
    for line in report:
        print(f"  {line}")
    print("\nDry-run complete. Nothing was written.")
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
    migrated = migrate_project_manifests(paths)
    if migrated:
        print(f"  Migrated: {', '.join(migrated)}")
    else:
        print("  No migrations needed.")

    # Step 2: Regenerate configs
    print("[2/4] Regenerating configs...")
    processed = regenerate_configs(paths)
    print(f"  Processed: {len(processed)} project(s)")

    # Step 3: Reload Caddy
    print("[3/4] Reloading Caddy...")
    try:
        caddy_reload(paths.caddy, paths.state)
        print("  Caddy reloaded.")
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    # Step 4: Restart projects
    print("[4/4] Restarting projects...")
    succeeded, failed_projects, skipped_locked = restart_projects(paths)
    if succeeded:
        print(f"  Restarted: {', '.join(succeeded)}")
    if skipped_locked:
        print(f"  Skipped (locked): {', '.join(skipped_locked)}")
    notify_locked_skips(paths, skipped_locked)
    if failed_projects:
        print(f"  FAILED: {', '.join(failed_projects)}")

    # Write version
    semver, commit = parse_version_string(new_version)
    write_installed_version(paths, semver, commit)

    log_operation(
        "upgrade", f"Apply {current_version} -> {new_version}", paths,
        detail={
            "migrated": migrated,
            "restarted": succeeded,
            "skipped_locked": skipped_locked,
            "failed": failed_projects,
        },
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
        print(f"  ERROR: Stash failed: {e}", file=sys.stderr)
        log_error("upgrade", f"Stash failed: {e}", paths)
        return 1

    # Step 2: Migrate manifests
    print("[2/6] Migrating manifests...")
    migrated = migrate_project_manifests(paths)
    if migrated:
        print(f"  Migrated: {', '.join(migrated)}")
    else:
        print("  No migrations needed.")

    # Step 3: Regenerate configs
    print("[3/6] Regenerating configs...")
    processed = regenerate_configs(paths)
    print(f"  Processed: {len(processed)} project(s)")

    # Step 4: Reload Caddy
    print("[4/6] Reloading Caddy...")
    try:
        caddy_reload(paths.caddy, paths.state)
        print("  Caddy reloaded.")
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    # Step 5: Restart projects
    print("[5/6] Restarting projects...")
    succeeded, failed_projects, skipped_locked = restart_projects(paths)
    if succeeded:
        print(f"  Restarted: {', '.join(succeeded)}")
    if skipped_locked:
        print(f"  Skipped (locked): {', '.join(skipped_locked)}")
    notify_locked_skips(paths, skipped_locked)
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
        detail={
            "migrated": migrated,
            "restarted": succeeded,
            "skipped_locked": skipped_locked,
            "failed": failed_projects,
        },
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
  --dry-run         Render manifest migrations and configs in memory and
                    report; writes nothing. The shim's pre-flight check.
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
