# SPDX-License-Identifier: Apache-2.0
"""boxmunge auto-update — check for and apply security releases.

Checks the boxmunge.dev version-check endpoint first, falling back to the
GitHub Releases API. Applies via upgrade flow. Run by a systemd timer every
6 hours.

NOTE: Full signature verification (cosign) will be added when the release
pipeline is active.
"""

import json
import sys
import urllib.error
import urllib.request
from typing import Any

from boxmunge.log import log_operation, log_error
from boxmunge.paths import BoxPaths
from boxmunge.version import read_installed_version, parse_version_string


GITHUB_REPO = "boxmunge/boxmunge"
RELEASES_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases"


class UpdateCheckError(Exception):
    """Raised when the update check cannot be performed."""


def _fetch_releases() -> list[dict[str, Any]]:
    """Fetch recent releases from GitHub API. Raises on failure."""
    req = urllib.request.Request(
        RELEASES_URL,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "boxmunge"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except urllib.error.URLError as e:
        raise UpdateCheckError(f"Cannot reach GitHub API: {e}") from e
    except json.JSONDecodeError as e:
        raise UpdateCheckError(f"Invalid response from GitHub API: {e}") from e


def _is_security_release(release: dict[str, Any]) -> bool:
    """Check if a release is tagged as a security fix."""
    body = (release.get("body") or "").lower()
    name = (release.get("name") or "").lower()
    return "[security]" in name or "[security]" in body


def _version_newer(candidate: str, current: str) -> bool:
    """Semver comparison. Returns False for unparseable versions."""
    def to_tuple(v: str) -> tuple[int, ...] | None:
        parts = v.split(".")
        try:
            return tuple(int(x) for x in parts)
        except ValueError:
            return None
    c = to_tuple(candidate)
    cur = to_tuple(current)
    if c is None or cur is None:
        return False
    # Pad to equal length for accurate comparison
    max_len = max(len(c), len(cur))
    c = c + (0,) * (max_len - len(c))
    cur = cur + (0,) * (max_len - len(cur))
    return c > cur


def _same_minor_line(candidate: str, current: str) -> bool:
    """Check if candidate is on the same major.minor line as current."""
    def to_minor(v: str) -> tuple[int, int] | None:
        parts = v.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            return (major, minor)
        except (ValueError, IndexError):
            return None
    c = to_minor(candidate)
    cur = to_minor(current)
    if c is None or cur is None:
        return False
    return c == cur


VERSION_CHECK_URL = "https://boxmunge.dev/v1/check"


def _check_via_endpoint(current_version: str) -> dict[str, Any]:
    """Query boxmunge.dev for update status. Raises UpdateCheckError on failure."""
    url = f"{VERSION_CHECK_URL}?v={current_version}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"boxmunge/{current_version}"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except urllib.error.URLError as e:
        raise UpdateCheckError(f"Cannot reach version-check service: {e}") from e
    except json.JSONDecodeError as e:
        raise UpdateCheckError(f"Invalid response from version-check service: {e}") from e


def _check_via_github(current_semver: str) -> dict[str, Any] | None:
    """Fallback: check GitHub Releases API for security updates."""
    releases = _fetch_releases()
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        if not _is_security_release(release):
            continue
        tag = release.get("tag_name", "").lstrip("v")
        if not _same_minor_line(tag, current_semver):
            continue
        if _version_newer(tag, current_semver):
            release_url = release.get("html_url", "")
            if not release_url.startswith(f"https://github.com/{GITHUB_REPO}/releases/"):
                continue
            return {"version": tag, "url": release_url, "name": release.get("name", "")}
    return None


def check_for_security_update(paths: BoxPaths) -> dict[str, Any] | None:
    """Check if a security update is available. Returns release info or None.

    Tries the boxmunge.dev endpoint first. Falls back to the GitHub Releases
    API if the endpoint is unreachable.
    """
    current = read_installed_version(paths)
    current_semver, _ = parse_version_string(current)

    # Primary: boxmunge.dev version-check service
    try:
        result = _check_via_endpoint(current_semver)
        if result.get("status") == "security_update_available" and result.get("security"):
            sec = result["security"]
            return {"version": sec["version"], "url": sec["url"], "name": f"v{sec['version']} [security]"}
        return None
    except UpdateCheckError:
        pass

    # Fallback: GitHub Releases API
    return _check_via_github(current_semver)


def run_auto_update(paths: BoxPaths) -> int:
    """Check for and apply security updates. Returns 0 on success."""
    print("Checking for security updates...")
    try:
        update = check_for_security_update(paths)
    except UpdateCheckError as e:
        print(f"ERROR: Update check failed: {e}")
        log_error("auto-update", f"Update check failed: {e}", paths)
        return 1

    if update is None:
        print("No security updates available.")
        return 0

    print(f"Security update available: {update['name']} ({update['version']})")
    log_operation("auto-update", f"Security release found: {update['version']}", paths)

    from boxmunge.commands.upgrade_cmd import run_upgrade
    result = run_upgrade(paths, skip_self_test=False)

    if result == 0:
        log_operation("auto-update", f"Security update applied: {update['version']}", paths)
        try:
            from boxmunge.config import load_config
            from boxmunge.pushover import send_notification
            config = load_config(paths)
            pushover = config.get("pushover", {})
            send_notification(
                pushover.get("user_key", ""), pushover.get("app_token", ""),
                "boxmunge security update applied",
                f"Updated to {update['version']}: {update['name']}",
            )
        except Exception:
            pass
    else:
        log_error("auto-update", f"Security update failed: {update['version']}", paths)

    return result


def cmd_auto_update(args: list[str]) -> None:
    """CLI entry point for auto-update command."""
    paths = BoxPaths()
    sys.exit(run_auto_update(paths))
