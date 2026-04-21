# SPDX-License-Identifier: Apache-2.0
"""Upgrade state management — blocklist and probation.

Reads and writes JSON state files in /opt/boxmunge/upgrade-state/.
Used by the bash shim (via CLI wrappers) and Python commands.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _read_json(path: Path) -> dict[str, Any]:
    """Read a JSON file, returning empty dict if missing or corrupt."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically."""
    from boxmunge.fileutil import atomic_write_text
    atomic_write_text(path, json.dumps(data, indent=2) + "\n")


# --- Blocklist ---

def is_blocklisted(paths: BoxPaths, version: str) -> bool:
    return version in _read_json(paths.blocklist)


def add_to_blocklist(paths: BoxPaths, version: str, reason: str) -> None:
    data = _read_json(paths.blocklist)
    data[version] = {
        "reason": reason,
        "failed_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(paths.blocklist, data)


def remove_from_blocklist(paths: BoxPaths, version: str) -> None:
    data = _read_json(paths.blocklist)
    data.pop(version, None)
    _write_json(paths.blocklist, data)


# --- Probation ---

def read_probation(paths: BoxPaths) -> dict[str, Any] | None:
    data = _read_json(paths.probation)
    return data if data else None


def write_probation(paths: BoxPaths, version: str, previous_slot: str, *, hours: int = 6) -> None:
    now = datetime.now(timezone.utc)
    _write_json(paths.probation, {
        "version": version,
        "started_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=hours)).isoformat(),
        "previous_slot": previous_slot,
    })


def clear_probation(paths: BoxPaths) -> None:
    if paths.probation.exists():
        paths.probation.unlink()
