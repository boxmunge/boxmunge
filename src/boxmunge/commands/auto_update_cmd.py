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

from boxmunge.config import ConfigError, version_check_enabled
from boxmunge.host_config_alert import load_for_job
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.paths import BoxPaths

_SCOPE = {"breakfix": "security and break-fix", "security": "security"}
# How long discovery waits for upgrade.lock. A readiness check (deploy's
# `upgrade-check`) holds it for at most about ten minutes, and the next one
# starts ten minutes after that one ends, so waiting this long means no
# check can hold off an update. A lock held past it is counted, and every
# LOCK_SKIPS_ALERT runs in a row (12 h) said as an error, as check-probation
# does for its own skips.
LOCK_WAIT_SECS = 900
LOCK_SKIPS_ALERT = 2
_LOCK_SKIPS_FILE = "auto-update-lock-skips"


def _lock_skipped(paths: BoxPaths) -> None:
    """Count a run that waited LOCK_WAIT_SECS for upgrade.lock in vain."""
    from boxmunge.fileutil import atomic_write_bytes
    skips = paths.upgrade_root / _LOCK_SKIPS_FILE
    try:
        count = int(skips.read_text())
    except (FileNotFoundError, ValueError):
        count = 0
    count += 1
    atomic_write_bytes(skips, f"{count}\n".encode(), 0o600, (os.geteuid(), os.getegid()), refuse_link=True)
    print(f"An upgrade is in progress (upgrade.lock held for over {LOCK_WAIT_SECS // 60} minutes); "
          "skipping this check.")
    if count % LOCK_SKIPS_ALERT:
        log_warning("auto-update", "Skipped: upgrade.lock held for the whole wait", paths,
                    detail={"in_a_row": count})
        return
    log_error("auto-update", f"auto-update could not take upgrade.lock {count} times in a row "
              f"(waiting {LOCK_WAIT_SECS // 60} minutes each time), so no update is installed. "
              "Find the holder as supervisor: sudo lslocks | grep upgrade.lock", paths)


def run_auto_update(paths: BoxPaths) -> int:
    """Check for and apply automatic updates. Returns 0 on success.

    Delegates discovery to boxmunge.upgrade_discovery.discover_update.
    Hands off to the boxmunge-upgrade shim via os.execvp on success.
    """
    from boxmunge.blocked_update import record_blocked
    from boxmunge.discovery_freshness import record_discovery
    from boxmunge.manual_update import record_manual
    from boxmunge.os_update_alert import record_os_updates
    from boxmunge.os_updates import inspect_os_updates
    from boxmunge.upgrade_discovery import auto_update_mode, discover_update
    from boxmunge.upgrade_state import UpgradeInProgress, UpgradeStateError, upgrade_lock
    # `health` is not scheduled, so this timer is where a box notices that
    # its OS updates stopped arriving. Checked first: an upgrade below execs
    # the shim and never returns.
    record_os_updates(paths, inspect_os_updates())
    try:
        # auto_update and version_check are all this reads, and load_config
        # always checks those: no other setting stops a box upgrading.
        config = load_for_job(paths, "auto-update")
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
    # exec: the shim takes it again itself (`run` waits for it as this does).
    try:
        with upgrade_lock(paths, wait=LOCK_WAIT_SECS):
            (paths.upgrade_root / _LOCK_SKIPS_FILE).unlink(missing_ok=True)
            result = discover_update(paths, mode=mode)
    except UpgradeInProgress:
        _lock_skipped(paths)
        return 0
    except UpgradeStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error("auto-update", str(e), paths)
        return 1
    action = result.get("action")
    record_discovery(paths, result)
    if action in ("upgrade", "up_to_date", "blocklisted"):
        record_manual(paths, result)

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
