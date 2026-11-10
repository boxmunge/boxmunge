# SPDX-License-Identifier: Apache-2.0
"""Has the version-check service given auto-update a usable answer lately?

Discovery installs nothing when the service answers with an error (a 429, a
5xx, a malformed body), because the GitHub fallback cannot see
circuit-breaker holds (boxmunge.upgrade_discovery); when the service cannot
be reached at all it falls back to GitHub, which sees only the holds the
maintainer has also marked ``[held]`` in a release title. Either
way a long run of failures must not go unnoticed: auto-update records each
discovery here, and the ``platform-updates`` health check warns (never
errors) once the service has gone ``STALE_AFTER`` without a usable answer.

State lives in ``state/update-discovery.json`` (deploy-owned, written
atomically): ``answered_at`` (last usable answer, or None), and
``failing_since`` / ``last_error`` (None while it answers).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths
from boxmunge.version_check_url import version_check_base
from boxmunge.fs_nofollow import read_text_nofollow_or_none

STALE_AFTER = timedelta(hours=48)
_KEYS = {"answered_at", "failing_since", "last_error"}


class DiscoveryStateError(ValueError):
    """state/update-discovery.json is unreadable or not in the expected shape."""


def _when(value: Any, path, key: str) -> datetime | None:
    if value is None:
        return None
    try:
        at = datetime.fromisoformat(value)
    except (TypeError, ValueError) as e:
        raise DiscoveryStateError(f"{path}: '{key}' is not a timestamp: {e}") from e
    if at.tzinfo is None:
        raise DiscoveryStateError(f"{path}: '{key}' has no timezone")
    return at


def _read(paths: BoxPaths) -> dict[str, Any] | None:
    path = paths.update_discovery_state
    try:
        raw = read_text_nofollow_or_none(path)
        if raw is None:
            return None
        state = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise DiscoveryStateError(f"{path}: unreadable: {e}") from e
    if not isinstance(state, dict) or set(state) != _KEYS:
        raise DiscoveryStateError(f"{path}: expected keys {sorted(_KEYS)}")
    if state["last_error"] is not None and not isinstance(state["last_error"], str):
        raise DiscoveryStateError(f"{path}: 'last_error' is not text")
    return {"answered_at": _when(state["answered_at"], path, "answered_at"),
            "failing_since": _when(state["failing_since"], path, "failing_since"),
            "last_error": state["last_error"]}


def record_discovery(paths: BoxPaths, result: dict[str, Any],
                     *, now: datetime | None = None) -> None:
    """Record one discover_update ``result``. A result the service did not
    shape (e.g. an unreadable blocklist after a good answer) changes nothing.
    A previous state file that cannot be read is replaced."""
    now = now or datetime.now(timezone.utc)
    if result.get("source") == "endpoint":
        state = {"answered_at": now, "failing_since": None, "last_error": None}
    elif "endpoint_error" in result:
        try:
            previous = _read(paths)
        except DiscoveryStateError:
            previous = None
        answered = previous["answered_at"] if previous else None
        since = (previous["failing_since"] if previous else None) or now
        state = {"answered_at": answered, "failing_since": since,
                 "last_error": str(result["endpoint_error"])}
    else:
        return
    atomic_write_text(paths.update_discovery_state, json.dumps(
        {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in state.items()},
        indent=2) + "\n")


def stale_discovery_warning(paths: BoxPaths, *, now: datetime | None = None) -> str | None:
    """Why auto-update's discovery needs a look, or None.

    Raises DiscoveryStateError when the state file is unreadable."""
    now = now or datetime.now(timezone.utc)
    state = _read(paths)
    if state is None or state["failing_since"] is None:
        return None
    if now - state["failing_since"] <= STALE_AFTER:
        return None
    answered = state["answered_at"]
    last = (f"last usable answer {answered.isoformat()}" if answered
            else "no usable answer recorded yet")
    return (f"the version-check service ({version_check_base()}) has given auto-update no "
            f"usable answer since {state['failing_since'].isoformat()} ({last}); last error: "
            f"{state['last_error']}. While it answers with errors no automatic update is "
            f"installed, and while it is unreachable releases come from GitHub, which "
            f"sees a circuit-breaker hold only once it is marked there too. A connection "
            f"error means this box cannot reach it (check DNS, firewall, proxy); an HTTP "
            f"5xx is on the service's side")
