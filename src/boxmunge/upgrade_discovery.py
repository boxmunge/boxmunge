# SPDX-License-Identifier: Apache-2.0
"""Upgrade discovery — finds the next version to install.

Single source of truth for "what version should we upgrade to?". The mode
says which release classes qualify:

- ``security`` — newest same-line security release (auto-update, break-fixes off);
- ``breakfix`` — newest same-line break-fix or security release (auto-update default);
- ``latest``   — newest release of any class on any line (manual upgrade).

The version-check endpoint is asked first. If it is unreachable or returns
a response that does not match its contract, the GitHub releases API is the
fallback, using the same rules: a release whose title or notes contain
``[security]`` is a security release, ``[breakfix]`` a break-fix release.
A fallback result carries ``endpoint_error`` so callers can log it.
"""
from __future__ import annotations

import json
import re
import urllib.request
from typing import Any

from boxmunge.config import auto_update_breakfix_enabled
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_state import is_blocklisted
from boxmunge.version import read_installed_version, parse_version_string


GITHUB_REPO = "boxmunge/boxmunge"
RELEASES_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases"
RELEASE_PAGE_PREFIX = f"https://github.com/{GITHUB_REPO}/releases/"
ENDPOINT_URL = "https://boxmunge.dev/v1/check"

RELEASE_CLASSES = ("feature", "breakfix", "security")
MODES = ("security", "breakfix", "latest")
# Which release classes each mode accepts.
_MODE_CLASSES = {
    "security": frozenset({"security"}),
    "breakfix": frozenset({"breakfix", "security"}),
    "latest": frozenset(RELEASE_CLASSES),
}
_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")


class EndpointContractError(ValueError):
    """The version-check endpoint answered with a response we cannot trust."""


# What makes a discovery source unusable: network failures and timeouts
# (URLError and socket timeouts are OSErrors), undecodable bodies, and
# responses that break the contract.
_SOURCE_ERRORS = (OSError, json.JSONDecodeError, UnicodeDecodeError, EndpointContractError)


def _vtuple(v: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return None


def _newer(candidate: str, current: str) -> bool:
    c, cur = _vtuple(candidate), _vtuple(current)
    if c is None or cur is None:
        return False
    n = max(len(c), len(cur))
    return c + (0,) * (n - len(c)) > cur + (0,) * (n - len(cur))


def _same_minor(candidate: str, current: str) -> bool:
    c, cur = _vtuple(candidate), _vtuple(current)
    return c is not None and cur is not None and c[:2] == cur[:2]


def _check_endpoint(current: str) -> dict[str, Any]:
    req = urllib.request.Request(
        f"{ENDPOINT_URL}?v={current}",
        headers={"User-Agent": f"boxmunge/{current}"},
    )
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())


def _endpoint_candidate(result: Any, mode: str) -> dict[str, Any] | None:
    """Read the field for this mode from a /v1/check response, strictly."""
    if not isinstance(result, dict):
        raise EndpointContractError("response is not a JSON object")
    for field in ("security", "breakfix", "latest"):
        if field not in result:
            raise EndpointContractError(
                f"response has no '{field}' field (version-check service out of date?)")
    offer = result[mode]
    if offer is None:
        return None
    if not isinstance(offer, dict):
        raise EndpointContractError(f"'{mode}' is not an object")
    version, url, cls = offer.get("version"), offer.get("url"), offer.get("class")
    if not isinstance(version, str) or not isinstance(url, str):
        raise EndpointContractError(f"'{mode}' lacks a version or url")
    if cls not in _MODE_CLASSES[mode]:
        raise EndpointContractError(f"'{mode}' offers a release of class {cls!r}")
    return {"version": version, "url": url, "class": cls}


def _github_release_class(release: dict[str, Any]) -> str:
    text = f"{release.get('name') or ''}\n{release.get('body') or ''}".lower()
    if "[security]" in text:
        return "security"
    if "[breakfix]" in text:
        return "breakfix"
    return "feature"


def _check_github(current: str, mode: str) -> dict[str, Any] | None:
    req = urllib.request.Request(
        RELEASES_URL,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "boxmunge"},
    )
    resp = urllib.request.urlopen(req, timeout=30)
    releases = json.loads(resp.read())
    if not isinstance(releases, list):
        raise EndpointContractError("GitHub releases response is not a list")
    best: dict[str, Any] | None = None
    for r in releases:
        if r.get("draft") or r.get("prerelease"):
            continue
        match = _TAG_RE.match(r.get("tag_name") or "")
        if not match:
            continue  # client tags (cli-v*) and anything not vX.Y.Z
        version = match.group(1)
        if not _newer(version, current):
            continue
        if mode != "latest" and not _same_minor(version, current):
            continue
        cls = _github_release_class(r)
        if cls not in _MODE_CLASSES[mode]:
            continue
        url = r.get("html_url") or ""
        if not url.startswith(RELEASE_PAGE_PREFIX):
            continue
        if best is None or _newer(version, best["version"]):
            best = {"version": version, "url": url, "class": cls}
    return best


def auto_update_mode(config: dict[str, Any]) -> str:
    """The discovery mode auto-update uses under this box's boxmunge.yml."""
    return "breakfix" if auto_update_breakfix_enabled(config) else "security"


def discover_update(paths: BoxPaths, mode: str) -> dict[str, Any]:
    """Find the next version to install under ``mode``. Returns a dict with action.

    Possible actions:
      - "upgrade": {action, version, url, class, source}
      - "up_to_date": {action, current_version, source}
      - "blocklisted": {action, version, class, source}
      - "error": {action, message}
    ``source`` is "endpoint" or "github"; a github result also carries
    ``endpoint_error`` (why the endpoint was not used).
    """
    if mode not in MODES:
        raise ValueError(f"unknown discovery mode {mode!r}; expected one of {MODES}")
    current, _ = parse_version_string(read_installed_version(paths))

    meta: dict[str, Any] = {"source": "endpoint"}
    try:
        candidate = _endpoint_candidate(_check_endpoint(current), mode)
    except _SOURCE_ERRORS as e:
        meta = {"source": "github", "endpoint_error": str(e)}
        try:
            candidate = _check_github(current, mode)
        except _SOURCE_ERRORS as gh:
            return {"action": "error",
                    "message": f"Cannot use boxmunge.dev ({e}) or GitHub ({gh})"}

    if candidate is None or not _newer(candidate["version"], current):
        return {"action": "up_to_date", "current_version": current, **meta}

    if is_blocklisted(paths, candidate["version"]):
        return {"action": "blocklisted", "version": candidate["version"],
                "class": candidate["class"], **meta}

    return {"action": "upgrade", **candidate, **meta}
