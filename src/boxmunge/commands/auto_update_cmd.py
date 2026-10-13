# SPDX-License-Identifier: Apache-2.0
"""boxmunge auto-update — check for and apply automatic platform releases.

Security releases are always applied. Break-fix releases (critical
non-security fixes) are applied unless boxmunge.yml sets
``auto_update.breakfix: false``. Feature releases are never applied here.

Thin orchestration layer: delegates discovery to upgrade_discovery and hands
off the upgrade itself to the boxmunge-upgrade shim via os.execvp, which
verifies the release signature, applies it, and runs probation, rollback
and blocklisting identically for every class. Run by a systemd timer every
6 hours.
"""

import os
import sys

from boxmunge.config import ConfigError, load_config
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.paths import BoxPaths

_SCOPE = {"breakfix": "security and break-fix", "security": "security"}


def run_auto_update(paths: BoxPaths) -> int:
    """Check for and apply automatic updates. Returns 0 on success.

    Delegates discovery to boxmunge.upgrade_discovery.discover_update.
    Hands off to the boxmunge-upgrade shim via os.execvp on success.
    """
    from boxmunge.upgrade_discovery import auto_update_mode, discover_update
    try:
        mode = auto_update_mode(load_config(paths))
    except ConfigError as e:
        print(f"ERROR: Cannot read auto-update policy: {e}", file=sys.stderr)
        log_error("auto-update", f"Cannot read auto-update policy: {e}", paths)
        return 1
    scope = _SCOPE[mode]
    print(f"Checking for {scope} updates...")
    result = discover_update(paths, mode=mode)
    action = result.get("action")

    if result.get("endpoint_error"):
        print(f"WARNING: version-check endpoint not used ({result['endpoint_error']}); "
              "discovered via GitHub releases instead.", file=sys.stderr)
        log_warning("auto-update", "Version-check endpoint not used; fell back to GitHub",
                    paths, detail={"endpoint_error": result["endpoint_error"]})

    if action == "up_to_date":
        print(f"No {scope} updates available.")
        return 0
    if action == "blocklisted":
        version = result["version"]
        print(f"Version {version} is blocklisted on this box, skipping.")
        log_operation("auto-update",
                      f"Skipped blocklisted version: {version}", paths,
                      detail={"version": version, "class": result["class"]})
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
    paths = BoxPaths()
    sys.exit(run_auto_update(paths))
