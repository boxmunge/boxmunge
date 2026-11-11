# SPDX-License-Identifier: Apache-2.0
"""What each KEV source last served, kept between refreshes.

kev_refresh needs it to tell two cases apart (CVE-03): a source ranked
earlier than the cache's own that serves an older catalog lacking cached
IDs may not have caught up (it serves what it served last time), or it
may have moved on without them (a newer catalog than its last one), while
the later source the cache came from invented them. Only the first is a
disagreement; the second is ranking, and its drops are withdrawals. It
also counts the runs a source was passed over that way since it last served
a catalog that was not (runs it did not answer do not count), so
an override of the first source cannot go on quietly.

File: state/kev/sources.json, beside the cache and the withdrawals, with
the same trust: {"sources": {URL: {"released_at", "disagreed_runs"}}}.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.paths import BoxPaths


class KevHistoryError(Exception):
    """The source history cannot be read or written; names the file."""


@dataclass(frozen=True)
class Served:
    released_at: datetime   # the dateReleased of the last catalog it served
    disagreed_runs: int     # runs passed over as stalled since it last served one
                            # that was not (runs it did not answer do not count)


def _entries(paths: BoxPaths) -> dict[str, dict[str, Any]]:
    path = paths.kev_sources
    try:
        # A link whose target is gone is not "no history yet": an empty
        # history would stop any source counting as stalled (CVE-03 reopened).
        raw = read_text_nofollow_or_none(path)
        if raw is None:
            return {}
        entries = json.loads(raw)["sources"]
        for entry in entries.values():
            datetime.fromisoformat(entry["released_at"])
            if not isinstance(entry["disagreed_runs"], int):
                raise ValueError("disagreed_runs is not a number")
        return entries
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise KevHistoryError(f"cannot read the KEV source history {path}: {e!r}") from e


def load_history(paths: BoxPaths) -> dict[str, Served]:
    """{source URL: what it last served}. Raises KevHistoryError."""
    return {url: Served(datetime.fromisoformat(e["released_at"]), e["disagreed_runs"])
            for url, e in _entries(paths).items()}


def note_served(paths: BoxPaths, url: str, released: datetime, *, disagreed: bool) -> Served:
    """Record that ``url`` served a catalog released ``released``, and
    whether it was passed over as disagreeing; return the new record.
    Raises KevHistoryError."""
    entries = _entries(paths)
    runs = entries.get(url, {}).get("disagreed_runs", 0) + 1 if disagreed else 0
    entries[url] = {"released_at": released.isoformat(), "disagreed_runs": runs}
    try:
        atomic_write_text(paths.kev_sources,
                          json.dumps({"sources": dict(sorted(entries.items()))}, indent=2) + "\n")
    except OSError as e:
        raise KevHistoryError(
            f"cannot write the KEV source history {paths.kev_sources}: {e}") from e
    return Served(released, runs)
