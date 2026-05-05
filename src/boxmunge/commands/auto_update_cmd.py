# SPDX-License-Identifier: Apache-2.0
"""boxmunge auto-update — check for and apply security releases.

Thin orchestration layer: delegates discovery to upgrade_discovery and hands
off the upgrade itself to the boxmunge-upgrade shim via os.execvp. Run by a
systemd timer every 6 hours.

NOTE: Full signature verification (cosign) will be added when the release
pipeline is active.
"""

import os
import sys

from boxmunge.log import log_operation, log_error
from boxmunge.paths import BoxPaths


def run_auto_update(paths: BoxPaths) -> int:
    """Check for and apply security updates. Returns 0 on success.

    Delegates discovery to boxmunge.upgrade_discovery.discover_update.
    Hands off to the boxmunge-upgrade shim via os.execvp on success.
    """
    print("Checking for security updates...")
    from boxmunge.upgrade_discovery import discover_update
    result = discover_update(paths, security_only=True)
    action = result.get("action")

    if action == "up_to_date":
        print("No security updates available.")
        return 0
    if action == "blocklisted":
        version = result["version"]
        print(f"Version {version} is blocklisted on this box, skipping.")
        log_operation("auto-update",
                      f"Skipped blocklisted version: {version}", paths)
        return 0
    if action == "error":
        msg = result.get("message", "unknown")
        print(f"ERROR: Update check failed: {msg}", file=sys.stderr)
        log_error("auto-update", f"Update check failed: {msg}", paths)
        return 1
    if action == "upgrade":
        version = result["version"]
        url = result["url"]
        print(f"Security update available: {version}")
        log_operation("auto-update", f"Security release found: {version}", paths)
        shim = str(paths.bin / "boxmunge-upgrade")
        os.execvp(shim, [shim, "run", version, url])
        return 1  # pragma: no cover — execvp doesn't return on success
    # Defensive: unknown action.
    print(f"ERROR: Unknown discovery action: {action}", file=sys.stderr)
    return 1


def cmd_auto_update(args: list[str]) -> None:
    """CLI entry point for auto-update command."""
    paths = BoxPaths()
    sys.exit(run_auto_update(paths))
