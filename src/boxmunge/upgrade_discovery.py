# SPDX-License-Identifier: Apache-2.0
"""Upgrade discovery — finds the next version to install.

Single source of truth for "what version should we upgrade to?". The mode
says which release classes qualify:

- ``security`` — newest reachable security release (auto-update, break-fixes off);
- ``breakfix`` — newest reachable break-fix or security release (auto-update default);
- ``latest``   — newest release of any class on any line (manual upgrade).

A release is reachable when it has the box's major version and no release
between the box and it (it included) is breaking; it may be on a newer
minor line (see boxmunge.release_selection). Every result also carries
``blocked``: the newest security or break-fix release auto-update may not
install, and why, or None.

The version-check endpoint is asked first. Its answer also carries the
releases its circuit breaker holds (``held``): a held release is never
installed, in any mode. Only when the endpoint cannot be reached at all (no
HTTP answer: DNS, connection or timeout failure) is the GitHub releases API
the fallback, using the same rules on the ``[security]``, ``[breakfix]`` and
``[breaking]`` markers in release titles and notes; a fallback result carries
``endpoint_error`` so callers can log it. An answer the box cannot use (an
HTTP error such as the service's own 429, or a body that breaks the contract)
is an error, not a reason to ask GitHub: GitHub cannot know about holds, so
its answer could install the very release the maintainer withdrew. The box
retries on its next check. The trade-off: a security release waits while the
service answers with errors, rather than a held (known-broken) release being
installed fleet-wide.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from boxmunge.config import auto_update_breakfix_enabled
from boxmunge.paths import BoxPaths
from boxmunge.version_check_url import version_check_base
from boxmunge.release_selection import (
    AUTO_CLASSES, GITHUB_REPO, MODE_CLASSES, MODES, VERSION_RE, find_blocked, newer,
    parse_github_releases, select,
)
from boxmunge.upgrade_state import UpgradeStateError, is_blocklisted
from boxmunge.version import read_installed_version, parse_version_string


RELEASES_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases"


class EndpointContractError(ValueError):
    """The version-check endpoint answered with a response we cannot trust."""


# What makes GitHub unusable: network failures and timeouts (URLError and
# socket timeouts are OSErrors), undecodable bodies, and responses that break
# the contract.
_SOURCE_ERRORS = (OSError, json.JSONDecodeError, UnicodeDecodeError, EndpointContractError)


def _check_endpoint(current: str) -> Any:
    """The decoded /v1/check answer.

    Raises OSError when no answer arrived (the only case discovery falls back
    to GitHub for) and EndpointContractError for an answer it cannot use.
    """
    req = urllib.request.Request(
        f"{version_check_base()}/v1/check?v={current}",
        headers={"User-Agent": f"boxmunge/{current}"},
    )
    try:
        raw = urllib.request.urlopen(req, timeout=10).read()
    except urllib.error.HTTPError as e:  # an answer, not an outage
        raise EndpointContractError(f"it answered HTTP {e.code} ({e.reason})") from e
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise EndpointContractError(f"its answer is not JSON ({e})") from e


def _endpoint_candidate(result: dict[str, Any], mode: str) -> dict[str, Any] | None:
    """Read the field for this mode from a /v1/check response, strictly."""
    offer = result[mode]
    if offer is None:
        return None
    if not isinstance(offer, dict):
        raise EndpointContractError(f"'{mode}' is not an object")
    version, url, cls = offer.get("version"), offer.get("url"), offer.get("class")
    if not isinstance(version, str) or not isinstance(url, str):
        raise EndpointContractError(f"'{mode}' lacks a version or url")
    if cls not in MODE_CLASSES[mode]:
        raise EndpointContractError(f"'{mode}' offers a release of class {cls!r}")
    return {"version": version, "url": url, "class": cls}


def _endpoint_blocked(blocked: Any) -> dict[str, Any] | None:
    """Read ``blocked`` from a /v1/check response, strictly."""
    if blocked is None:
        return None
    if not isinstance(blocked, dict):
        raise EndpointContractError("'blocked' is not an object")
    version, url, cls = blocked.get("version"), blocked.get("url"), blocked.get("class")
    reason = blocked.get("reason")
    if not isinstance(version, str) or not VERSION_RE.match(version):
        raise EndpointContractError("'blocked' lacks an X.Y.Z version")
    if not isinstance(url, str):
        raise EndpointContractError("'blocked' lacks a url")
    if cls not in AUTO_CLASSES:
        raise EndpointContractError(f"'blocked' names a release of class {cls!r}")
    if not isinstance(reason, dict) or len(reason) != 1:
        raise EndpointContractError("'blocked' reason must name exactly one cause")
    if "breaking_release" in reason:
        cause = reason["breaking_release"]
        if not isinstance(cause, str) or not VERSION_RE.match(cause):
            raise EndpointContractError("'blocked' breaking_release is not X.Y.Z")
    elif "major" in reason:
        if type(reason["major"]) is not int:
            raise EndpointContractError("'blocked' major is not an integer")
    else:
        raise EndpointContractError(f"'blocked' has unknown reason {sorted(reason)}")
    return {"version": version, "url": url, "class": cls, "reason": dict(reason)}


def _endpoint_held(held: Any) -> list[str]:
    """Read the optional ``held`` list from a /v1/check response, strictly."""
    if not isinstance(held, list):
        raise EndpointContractError("'held' is not a list")
    versions = []
    for entry in held:
        if (not isinstance(entry, dict) or not isinstance(entry.get("version"), str)
                or not VERSION_RE.match(entry["version"])
                or not isinstance(entry.get("reason"), str)):
            raise EndpointContractError("'held' entries need an X.Y.Z version and a reason")
        versions.append(entry["version"])
    return versions


def _read_endpoint(
    result: Any, mode: str,
) -> tuple[dict[str, Any] | None, dict | None, list[str]]:
    """(candidate, blocked, held versions) from a /v1/check response."""
    if not isinstance(result, dict):
        raise EndpointContractError("response is not a JSON object")
    for field in ("security", "breakfix", "latest", "blocked"):
        if field not in result:
            raise EndpointContractError(
                f"response has no '{field}' field (version-check service out of date?)")
    return (_endpoint_candidate(result, mode), _endpoint_blocked(result["blocked"]),
            _endpoint_held(result.get("held", [])))


def _check_github(current: str, mode: str) -> tuple[dict[str, Any] | None, dict | None]:
    """(candidate, blocked) from the GitHub releases list."""
    req = urllib.request.Request(
        RELEASES_URL,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "boxmunge"},
    )
    resp = urllib.request.urlopen(req, timeout=30)
    raw = json.loads(resp.read())
    if not isinstance(raw, list):
        raise EndpointContractError("GitHub releases response is not a list")
    releases = parse_github_releases(raw)
    return select(releases, current, mode), find_blocked(releases, current)


def auto_update_mode(config: dict[str, Any]) -> str:
    """The discovery mode auto-update uses under this box's boxmunge.yml."""
    return "breakfix" if auto_update_breakfix_enabled(config) else "security"


def discover_update(paths: BoxPaths, mode: str) -> dict[str, Any]:
    """Find the next version to install under ``mode``. Returns a dict with action.

    Possible actions:
      - "upgrade": {action, version, url, class, ...}
      - "up_to_date": {action, ...}
      - "blocklisted": {action, version, class, ...}
      - "error": {action, message}
    Every action but "error" also carries ``current_version``, ``blocked``
    (see the module docstring) and ``source`` ("endpoint" or "github"); a
    github result also carries ``endpoint_error`` (why the endpoint was not
    used).
    """
    if mode not in MODES:
        raise ValueError(f"unknown discovery mode {mode!r}; expected one of {MODES}")
    current, _ = parse_version_string(read_installed_version(paths))

    meta: dict[str, Any] = {"source": "endpoint"}
    held: list[str] = []
    try:
        candidate, blocked, held = _read_endpoint(_check_endpoint(current), mode)
    except EndpointContractError as e:
        return {"action": "error", "message": _unusable_answer(e)}
    except OSError as e:  # no answer at all: the service is unreachable
        meta = {"source": "github", "endpoint_error": str(e)}
        try:
            candidate, blocked = _check_github(current, mode)
        except _SOURCE_ERRORS as gh:
            return {"action": "error",
                    "message": f"Cannot use boxmunge.dev ({e}) or GitHub ({gh})"}
    meta = {"current_version": current, "blocked": blocked, **meta}
    if held:
        meta["held"] = held

    if candidate is not None and candidate["version"] in held:
        return {"action": "error", "message": (
            f"Release {candidate['version']} is held by the version-check circuit "
            "breaker (withdrawn as broken); not installing it. It is offered again "
            "once the hold is reset.")}
    if candidate is None or not newer(candidate["version"], current):
        return {"action": "up_to_date", **meta}

    try:
        blocklisted = is_blocklisted(paths, candidate["version"])
    except UpgradeStateError as e:
        return {"action": "error", "message": f"Cannot read the upgrade blocklist: {e}"}
    if blocklisted:
        return {"action": "blocklisted", "version": candidate["version"],
                "class": candidate["class"], **meta}

    return {"action": "upgrade", **candidate, **meta}


def _unusable_answer(error: EndpointContractError) -> str:
    return (f"The version-check service at {version_check_base()} gave an answer this "
            f"box cannot use: {error}. GitHub is not asked instead: it cannot know "
            "which releases the service has held as broken. Nothing is installed; "
            "auto-update retries on its next check, or run `boxmunge upgrade` again later.")
