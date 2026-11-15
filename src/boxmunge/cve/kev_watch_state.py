# SPDX-License-Identifier: Apache-2.0
"""What the KEV watch last saw: ``state/kev/watch.json``.

``{"seen_at": ISO8601, "cve_ids": [...], "failing": {project: {"attempted_at":
ISO8601, "alerted_on": "YYYY-MM-DD"|null}}}``.

``cve_ids`` is every CVE any known-exploited source listed as of the last
tick (``seen_at``). It only grows: a source that goes stale and comes back
must not make its listings look new. The cost: a CVE a source withdrew and
later lists again is not new to the watch, and waits for the nightly scan.

``failing`` holds each project the watch could not rescan cleanly: when it
last tried (so a nightly scan completed after that, which covers the CVE,
ends the retries) and the day its scan-failure alert was last sent (so it is
sent once a day, not every tick).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError


@dataclass(frozen=True)
class Failing:
    attempted_at: datetime
    alerted_on: date | None


@dataclass(frozen=True)
class WatchState:
    seen_at: datetime
    cve_ids: frozenset[str]
    failing: dict[str, Failing] = field(default_factory=dict)


def _aware(value: Any, what: str) -> datetime:
    when = datetime.fromisoformat(value)
    if when.tzinfo is None:
        raise ValueError(f"{what} {value!r} has no timezone")
    return when


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
        failing = {
            project: Failing(
                _aware(f["attempted_at"], "attempted_at"),
                None if f["alerted_on"] is None else date.fromisoformat(f["alerted_on"]))
            for project, f in data["failing"].items()}
        return WatchState(_aware(data["seen_at"], "seen_at"), frozenset(ids), failing)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise StateError(
            f"cannot read the KEV watch record {path}: {e!r}; remove it to start the "
            f"watch afresh (it then records the listed CVEs and rescans nothing)") from e


def write_watch(paths: BoxPaths, state: WatchState) -> None:
    """Write the record atomically. Raises StateError."""
    body = {
        "seen_at": state.seen_at.isoformat(),
        "cve_ids": sorted(state.cve_ids),
        "failing": {p: {"attempted_at": f.attempted_at.isoformat(),
                        "alerted_on": None if f.alerted_on is None else f.alerted_on.isoformat()}
                    for p, f in sorted(state.failing.items())},
    }
    try:
        paths.kev_watch.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(paths.kev_watch, json.dumps(body, indent=2) + "\n")
    except OSError as e:
        raise StateError(f"cannot write the KEV watch record {paths.kev_watch}: {e}") from e
