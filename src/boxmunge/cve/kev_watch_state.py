# SPDX-License-Identifier: Apache-2.0
"""What the KEV watch last saw: ``state/kev/watch.json``.

``{"seen_at": ISO8601, "cve_ids": [...]}``: every CVE any known-exploited
source listed as of the watch's last tick (``seen_at``). The set only grows:
a source that goes stale and comes back must not make its listings look new.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError


@dataclass(frozen=True)
class WatchState:
    seen_at: datetime
    cve_ids: frozenset[str]


def read_watch(paths: BoxPaths) -> WatchState | None:
    """The last tick's record, or None before the first tick.
    Raises StateError, naming the file, when it cannot be used."""
    path = paths.kev_watch
    try:
        raw = read_text_nofollow_or_none(path)
        if raw is None:
            return None
        data = json.loads(raw)
        ids = data["cve_ids"]
        if not isinstance(ids, list) or not all(isinstance(c, str) for c in ids):
            raise ValueError("cve_ids must be a list of CVE id strings")
        seen_at = datetime.fromisoformat(data["seen_at"])
        if seen_at.tzinfo is None:
            raise ValueError(f"seen_at {data['seen_at']!r} has no timezone")
        return WatchState(seen_at, frozenset(ids))
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise StateError(
            f"cannot read the KEV watch record {path}: {e!r}; remove it to start the "
            f"watch afresh (it then records the listed CVEs and rescans nothing)") from e


def write_watch(paths: BoxPaths, state: WatchState) -> None:
    """Write the record atomically. Raises StateError."""
    body = {"seen_at": state.seen_at.isoformat(), "cve_ids": sorted(state.cve_ids)}
    try:
        paths.kev_watch.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(paths.kev_watch, json.dumps(body, indent=2) + "\n")
    except OSError as e:
        raise StateError(f"cannot write the KEV watch record {paths.kev_watch}: {e}") from e
