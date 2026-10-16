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
    ManifestMigration,
    Regeneration,
    Restart,
    UpgradeGateError,
    check_upgrade,
    migrate_project_manifests,
    notify_locked_skips,
    notify_refused,
    regenerate_configs,
    restart_projects,
)
from boxmunge.docker import caddy_reload, DockerError
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import ManifestError
from boxmunge.migration import MigrationError
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


def _gate_failed(paths: BoxPaths, error: Exception) -> int:
    """Report a failed upgrade gate. Non-zero makes the shim roll back."""
    print(f"ERROR: upgrade failed: {error}", file=sys.stderr)
    log_error("upgrade", f"Upgrade failed: {error}", paths)
    return 1


def _migrate_regenerate_reload(
    paths: BoxPaths, step: int, total: int,
) -> tuple[ManifestMigration, Regeneration]:
    """Steps shared by --apply and the full flow. Any failure raises: a
    project left on stale configs, or a Caddy that did not take the new
    ones, is not an upgrade that should report success."""
    print(f"[{step}/{total}] Migrating manifests...")
    migrated = migrate_project_manifests(paths)
    if migrated.written:
        print(f"  Migrated: {', '.join(migrated.written)}")
    if migrated.in_memory:
        print(f"  Migrated in memory (git; update manifest.yml in the repository): "
              f"{', '.join(migrated.in_memory)}")
    if not migrated.written and not migrated.in_memory:
        print("  No migrations needed.")

    print(f"[{step + 1}/{total}] Regenerating configs...")
    regen = regenerate_configs(paths)
    print(f"  Processed: {len(regen.processed)} project(s)")
    for name, why in sorted(regen.refused.items()):
        print(f"  REFUSED: {name}: {why}")
    if regen.refused:
        print("  Refused projects keep their previous configs and running "
              "containers and are not restarted. Fix compose.yml and redeploy.")

    print(f"[{step + 2}/{total}] Reloading Caddy...")
    try:
        caddy_reload(paths.caddy, paths.state)
    except DockerError as e:
        raise UpgradeGateError(f"Caddy reload failed: {e}") from e
    print("  Caddy reloaded.")
    return migrated, regen


def _restart(paths: BoxPaths, step: int, total: int, refused: dict[str, str]) -> Restart:
    print(f"[{step}/{total}] Restarting projects...")
    restart = restart_projects(paths, refused=refused)
    if restart.succeeded:
        print(f"  Restarted: {', '.join(restart.succeeded)}")
    if restart.skipped_locked:
        print(f"  Skipped (locked): {', '.join(restart.skipped_locked)}")
    if restart.monitor_stopped:
        print(f"  Not restarted (stopped by the health monitor; use `recover`): "
              f"{', '.join(restart.monitor_stopped)}")
    if refused:
        print(f"  Not restarted (compose refused): {', '.join(sorted(refused))}")
    notify_locked_skips(paths, restart.skipped_locked)
    notify_refused(paths, refused)
    if restart.failed:
        print(f"  FAILED: {', '.join(restart.failed)}", file=sys.stderr)
    return restart


def _finish(paths: BoxPaths, label: str, migrated: ManifestMigration, regen: Regeneration,
            restart: Restart, new_version: str) -> int:
    """Record the new version, but only when every project restarted."""
    log_operation(
        "upgrade", label, paths,
        detail={
            "migrated": migrated.written,
            "migrated_in_memory": migrated.in_memory,
            "restarted": restart.succeeded,
            "skipped_locked": restart.skipped_locked,
            "monitor_stopped": restart.monitor_stopped,
            "refused": sorted(regen.refused),
            "failed": restart.failed,
        },
    )
    if restart.failed:
        return _gate_failed(paths, UpgradeGateError(
            f"projects failed to restart: {', '.join(restart.failed)}"))
    semver, commit = parse_version_string(new_version)
    write_installed_version(paths, semver, commit)
    return 0


def _run_apply(paths: BoxPaths, current_version: str, new_version: str) -> int:
    """Run migrate/regen/reload/restart/version-write only.

    The upgrade shim handles stash creation, health checks, and rollback
    externally, so we skip those here. Returns 0 on success and 1 if any
    step failed, which makes the shim roll back.
    """
    print("boxmunge upgrade --apply")
    print("========================\n")
    print(f"  Current: {current_version}")
    print(f"  New:     {new_version}\n")
    try:
        migrated, regen = _migrate_regenerate_reload(paths, 1, 4)
    except (ManifestError, MigrationError, UpgradeGateError) as e:
        return _gate_failed(paths, e)
    restart = _restart(paths, 4, 4, regen.refused)
    return _finish(paths, f"Apply {current_version} -> {new_version}",
                   migrated, regen, restart, new_version)


def _run_full(
    paths: BoxPaths,
    current_version: str,
    new_version: str,
    skip_self_test: bool,
) -> int:
    """Run the complete six-step upgrade flow."""
    print("[1/6] Creating stash...")
    try:
        archive = create_stash(paths)
        print(f"  Stash: {archive.name}")
    except Exception as e:
        print(f"  ERROR: Stash failed: {e}", file=sys.stderr)
        log_error("upgrade", f"Stash failed: {e}", paths)
        return 1

    try:
        migrated, regen = _migrate_regenerate_reload(paths, 2, 6)
    except (ManifestError, MigrationError, UpgradeGateError) as e:
        return _gate_failed(paths, e)
    restart = _restart(paths, 5, 6, regen.refused)
    prune_stashes(paths, keep=5)

    print("\n[6/6] Post-upgrade validation")
    if skip_self_test:
        print("  Self-test skipped.")
    else:
        print("\nRunning self-test...")
        if run_self_test(paths) != 0:
            return _gate_failed(paths, UpgradeGateError("self-test failed"))

    print("\nRunning health check...")
    if run_health(paths) == 2:
        return _gate_failed(paths, UpgradeGateError("health check found critical issues"))

    rc = _finish(paths, f"Upgrade {current_version} -> {new_version}",
                 migrated, regen, restart, new_version)
    if rc == 0:
        print(f"\nUpgrade complete: {current_version} -> {new_version}")
    return rc


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
