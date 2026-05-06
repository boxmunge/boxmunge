# SPDX-License-Identifier: Apache-2.0
"""One-time 24-hour CVE-policy migration grace window.

When operators upgrade to the version where CVE policy first ships,
projects suddenly become subject to scan-and-quarantine logic that did
not exist before. To avoid surprising mass-quarantine on the first
03:00 cron run after upgrade, we apply a single 24-hour grace window:

* The first CVE scan after the feature lands creates a grace marker
  (lazy init — never on install). During grace, dispositions are
  computed normally but quarantine actions and per-project transition
  alerts are suppressed; a single fleet-level "heads-up" alert
  summarises what *would* have quarantined.
* After 24 hours, full enforcement resumes. The marker file remains as
  an audit record but ``is_active`` returns False.

This grace window is one-time, full stop: once ``expires_at < now``
we never re-init. Lazy bootstrapping (here, not in ``install.sh``)
prevents an operator from dodging enforcement by repeated upgrades.

The state file lives at ``state/cve-grace.json`` (single, fleet-wide):

    {
      "installed_at": "2026-05-06T12:00:00+00:00",
      "expires_at":   "2026-05-07T12:00:00+00:00",
      "heads_up_sent": false
    }

Malformed JSON raises ``GraceError`` — callers decide whether to abort
the scan or proceed without grace. The user's preference is to abort
when grace state is corrupt, so the operator is never led to believe
they are in grace when they are not.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boxmunge.fileutil import atomic_write_text

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


_LOGGER = logging.getLogger("boxmunge")

GRACE_DURATION = timedelta(hours=24)


# ---------- exceptions ----------


class GraceError(Exception):
    """Grace state file is malformed or unreadable."""


# ---------- value type ----------


@dataclass(frozen=True)
class GraceState:
    """Snapshot of the migration grace window."""

    installed_at: datetime
    expires_at: datetime
    heads_up_sent: bool

    def is_active(self, *, now: datetime) -> bool:
        """True iff ``now`` is strictly before ``expires_at``.

        At the boundary (``now == expires_at``) the grace is *over* —
        treat it as inactive so enforcement resumes deterministically.
        """
        return now < self.expires_at


# ---------- path helper ----------


def grace_state_path(paths: "BoxPaths") -> Path:
    """Return the path to the singleton grace state file."""
    return paths.cve_grace_state


# ---------- I/O ----------


def _parse_iso(value: Any, field: str) -> datetime:
    """Parse a stored ISO-8601 timestamp; require a timezone-aware result."""
    if not isinstance(value, str) or not value:
        raise GraceError(
            f"grace state field {field!r} is missing or not a string",
        )
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as e:
        raise GraceError(
            f"grace state field {field!r} is not a valid ISO timestamp: {e}",
        ) from e
    if dt.tzinfo is None:
        # We always write with tzinfo; a naive timestamp on read indicates
        # tampering or corruption — fail loudly rather than guess UTC.
        raise GraceError(
            f"grace state field {field!r} is missing timezone info",
        )
    return dt


def read_grace_state(paths: "BoxPaths") -> GraceState | None:
    """Read the grace state file.

    Returns ``None`` when the file does not exist (the "no scan has run
    since the feature landed" signal). Raises ``GraceError`` on malformed
    JSON or missing/invalid fields.
    """
    path = grace_state_path(paths)
    if not path.exists():
        return None
    try:
        raw = path.read_text()
    except OSError as e:
        raise GraceError(f"failed to read grace state file {path}: {e}") from e
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise GraceError(f"grace state file {path} is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise GraceError(
            f"grace state file {path} did not contain a JSON object",
        )
    installed_at = _parse_iso(data.get("installed_at"), "installed_at")
    expires_at = _parse_iso(data.get("expires_at"), "expires_at")
    heads_up_sent = data.get("heads_up_sent")
    if not isinstance(heads_up_sent, bool):
        raise GraceError(
            "grace state field 'heads_up_sent' is missing or not a bool",
        )
    return GraceState(
        installed_at=installed_at,
        expires_at=expires_at,
        heads_up_sent=heads_up_sent,
    )


def write_grace_state(paths: "BoxPaths", state: GraceState) -> None:
    """Persist the grace state atomically."""
    path = grace_state_path(paths)
    payload = {
        "installed_at": state.installed_at.isoformat(),
        "expires_at": state.expires_at.isoformat(),
        "heads_up_sent": state.heads_up_sent,
    }
    atomic_write_text(path, json.dumps(payload, indent=2) + "\n")


# ---------- bootstrap / mutation ----------


def init_grace_if_missing(
    paths: "BoxPaths", *, now: datetime,
) -> GraceState:
    """Return the existing grace state, or create one expiring in 24h.

    Canonical bootstrap entry-point: callers invoke this once at the
    start of a fleet scan. If the file already exists it is returned
    unchanged (we never re-init, even if it has expired).
    """
    existing = read_grace_state(paths)
    if existing is not None:
        return existing
    state = GraceState(
        installed_at=now,
        expires_at=now + GRACE_DURATION,
        heads_up_sent=False,
    )
    write_grace_state(paths, state)
    _LOGGER.info(
        "CVE migration grace initialised; full enforcement begins %s",
        state.expires_at.isoformat(),
    )
    return state


def mark_heads_up_sent(
    paths: "BoxPaths", state: GraceState,
) -> GraceState:
    """Persist ``heads_up_sent=True`` and return the updated state."""
    updated = GraceState(
        installed_at=state.installed_at,
        expires_at=state.expires_at,
        heads_up_sent=True,
    )
    write_grace_state(paths, updated)
    return updated
