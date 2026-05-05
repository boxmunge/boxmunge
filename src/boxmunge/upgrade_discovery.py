# SPDX-License-Identifier: Apache-2.0
"""Upgrade discovery — finds the next version to install.

Single source of truth for "what version should we upgrade to?" — used
by the auto-update systemd timer (security_only=True) and by the manual
boxmunge-upgrade shim (security_only=False, returns latest of any kind).

Replaces the inline-Python-in-bash logic that previously lived in
scripts/boxmunge-upgrade. That shape made bugs like v0.3.6/v0.3.7
ergonomically untestable.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from boxmunge.paths import BoxPaths
from boxmunge.upgrade_state import is_blocklisted
from boxmunge.version import read_installed_version, parse_version_string


GITHUB_REPO = "boxmunge/boxmunge"
RELEASES_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases"
ENDPOINT_URL = "https://boxmunge.dev/v1/check"


def _newer(candidate: str, current: str) -> bool:
    try:
        c = tuple(int(x) for x in candidate.split("."))
        cur = tuple(int(x) for x in current.split("."))
    except ValueError:
        return False
    n = max(len(c), len(cur))
    return c + (0,) * (n - len(c)) > cur + (0,) * (n - len(cur))


def _same_minor(candidate: str, current: str) -> bool:
    try:
        c = tuple(int(x) for x in candidate.split("."))[:2]
        cur = tuple(int(x) for x in current.split("."))[:2]
    except ValueError:
        return False
    return c == cur


def _check_endpoint(current: str) -> dict[str, Any]:
    req = urllib.request.Request(
        f"{ENDPOINT_URL}?v={current}",
        headers={"User-Agent": f"boxmunge/{current}"},
    )
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())


def _check_github(current: str, security_only: bool) -> dict[str, Any] | None:
    req = urllib.request.Request(
        RELEASES_URL,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "boxmunge"},
    )
    resp = urllib.request.urlopen(req, timeout=30)
    releases = json.loads(resp.read())
    for r in releases:
        if r.get("draft") or r.get("prerelease"):
            continue
        tag = r.get("tag_name", "").lstrip("v")
        if not _same_minor(tag, current):
            continue
        if not _newer(tag, current):
            continue
        body = (r.get("body") or "").lower()
        name = (r.get("name") or "").lower()
        is_security = "[security]" in body or "[security]" in name
        if security_only and not is_security:
            continue
        url = r.get("html_url", "")
        if not url.startswith(f"https://github.com/{GITHUB_REPO}/releases/"):
            continue
        return {"version": tag, "url": url, "is_security": is_security}
    return None


def discover_update(
    paths: BoxPaths, security_only: bool = False,
) -> dict[str, Any]:
    """Find the next version to install. Returns a dict with action.

    Possible actions:
      - "upgrade": {action, version, url, is_security}
      - "up_to_date": {action, current_version}
      - "blocklisted": {action, version}
      - "error": {action, message}
    """
    current_full = read_installed_version(paths)
    current, _ = parse_version_string(current_full)

    candidate: dict[str, Any] | None = None

    try:
        result = _check_endpoint(current)
        latest = result.get("latest")
        security = result.get("security")
        if security_only:
            if security and security.get("version"):
                candidate = {
                    "version": security["version"],
                    "url": security["url"],
                    "is_security": True,
                }
        else:
            if latest and latest.get("version"):
                candidate = {
                    "version": latest["version"],
                    "url": latest["url"],
                    "is_security": bool(security and security.get("version") == latest["version"]),
                }
    except (urllib.error.URLError, json.JSONDecodeError):
        # Fall back to GitHub.
        try:
            candidate = _check_github(current, security_only=security_only)
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            return {"action": "error",
                    "message": f"Cannot reach boxmunge.dev or GitHub: {e}"}

    if candidate is None:
        return {"action": "up_to_date", "current_version": current}

    if not _newer(candidate["version"], current):
        return {"action": "up_to_date", "current_version": current}

    if is_blocklisted(paths, candidate["version"]):
        return {"action": "blocklisted", "version": candidate["version"]}

    return {
        "action": "upgrade",
        "version": candidate["version"],
        "url": candidate["url"],
        "is_security": candidate["is_security"],
    }
