# SPDX-License-Identifier: Apache-2.0
"""boxmunge auto-update — check for and apply automatic platform releases.

Security releases are always applied. Break-fix releases (important
fixes that prevent issues) are applied unless boxmunge.yml sets
``auto_update.breakfix: false``. Feature releases are never applied here,
and neither is any release across a breaking release or into a new major
version. When such a security or break-fix release is all there is, the
operator is alerted instead (boxmunge.blocked_update). With
``version_check.enabled: false`` it discovers nothing and says so. Every run also checks
that OS security updates are arriving and alerts when they are not
(boxmunge.os_update_alert).

Thin orchestration layer: delegates discovery to upgrade_discovery and hands
off the upgrade itself to the boxmunge-upgrade shim via os.execvp, which
verifies the release signature, applies it, and runs probation, rollback
and blocklisting identically for every class. Run by a systemd timer every
6 hours.
"""

import os
import sys

from boxmunge.config import ConfigError, load_config, version_check_enabled
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.paths import BoxPaths

_SCOPE = {"breakfix": "security and break-fix", "security": "security"}


def run_auto_update(paths: BoxPaths) -> int:
    """Check for and apply automatic updates. Returns 0 on success.

    Delegates discovery to boxmunge.upgrade_discovery.discover_update.
    Hands off to the boxmunge-upgrade shim via os.execvp on success.
    """
    from boxmunge.blocked_update import record_blocked
    from boxmunge.discovery_freshness import record_discovery
    from boxmunge.os_update_alert import record_os_updates
    from boxmunge.os_updates import inspect_os_updates
    from boxmunge.upgrade_discovery import auto_update_mode, discover_update
    from boxmunge.upgrade_state import UpgradeInProgress, UpgradeStateError, upgrade_lock
    # `health` is not scheduled, so this timer is where a box notices that
    # its OS updates stopped arriving. Checked first: an upgrade below execs
    # the shim and never returns.
    record_os_updates(paths, inspect_os_updates())
    try:
        config = load_config(paths)
    except ConfigError as e:
        print(f"ERROR: Cannot read auto-update policy: {e}", file=sys.stderr)
        log_error("auto-update", f"Cannot read auto-update policy: {e}", paths)
        return 1
    if not version_check_enabled(config):
        from boxmunge.version_check_optout import OFF
        print(f"Skipped: {OFF}.")
        log_operation("auto-update", f"Skipped: {OFF}", paths)
        return 0
    mode = auto_update_mode(config)
    scope = _SCOPE[mode]
    print(f"Checking for {scope} updates...")
    # Discover under upgrade.lock so a check never runs against a half-swapped
    # venv or a blocklist the shim is writing. The lock is released before
    # exec: the shim takes it again itself.
    try:
        with upgrade_lock(paths):
            result = discover_update(paths, mode=mode)
    except UpgradeInProgress:
        print("An upgrade is in progress; skipping this check.")
        log_operation("auto-update", "Skipped: upgrade in progress", paths)
        return 0
    except UpgradeStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error("auto-update", str(e), paths)
        return 1
    action = result.get("action")
    record_discovery(paths, result)

    if result.get("endpoint_error"):
        print(f"WARNING: version-check endpoint not used ({result['endpoint_error']}); "
              "discovered via GitHub releases instead.", file=sys.stderr)
        log_warning("auto-update", "Version-check endpoint not used; fell back to GitHub",
                    paths, detail={"endpoint_error": result["endpoint_error"]})

    if result.get("held"):
        held = ", ".join(result["held"])
        by = ("the version-check circuit breaker" if result["source"] == "endpoint"
              else "[held] in the GitHub release title")
        print(f"Release(s) {held} held by {by}; not installed.")
        log_operation("auto-update", f"Release(s) {held} held by {by}",
                      paths, detail={"held": result["held"], "source": result["source"]})

    if action == "up_to_date":
        print(f"No {scope} updates available.")
        record_blocked(paths, result)
        return 0
    if action == "blocklisted":
        version = result["version"]
        print(f"Version {version} is blocklisted on this box, skipping.")
        log_operation("auto-update",
                      f"Skipped blocklisted version: {version}", paths,
                      detail={"version": version, "class": result["class"]})
        record_blocked(paths, result)
        return 0
    if action == "error":
        msg = result.get("message", "unknown")
        print(f"ERROR: Update check failed: {msg}", file=sys.stderr)
        log_error("auto-update", f"Update check failed: {msg}", paths)
        return 1
    if action == "upgrade":
        version, url, release_class = result["version"], result["url"], result["class"]
        print(f"Applying {release_class} release {version}")
        log_operation("auto-update", f"Applying {release_class} release {version}", paths,
                      detail={"version": version, "class": release_class,
                              "policy": mode, "source": result["source"]})
        shim = str(paths.bin / "boxmunge-upgrade")
        os.execvp(shim, [shim, "run", version, url, release_class])
        return 1  # pragma: no cover — execvp doesn't return on success
    # Defensive: unknown action.
    print(f"ERROR: Unknown discovery action: {action}", file=sys.stderr)
    return 1


def cmd_auto_update(args: list[str]) -> None:
    """CLI entry point for auto-update command."""
    from boxmunge.commands.argv import parse_args
    parse_args("auto-update", args)
    paths = BoxPaths()
    sys.exit(run_auto_update(paths))
