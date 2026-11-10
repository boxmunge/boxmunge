# SPDX-License-Identifier: Apache-2.0
"""CVEs a KEV refresh withdrew from the catalog, kept until it lists them again.

One source can drop an entry (up to KEV_MAX_REMOVALS per refresh are
accepted), and under balanced the drop alone would lift a quarantine held
for it. The refresh records each withdrawal here before it caches the new
catalog, so every later scan and the deploy gate can hold such a quarantine
until `security resume` accepts it, however many runs later that is
(commands/kev_withdrawal.py). An entry is removed when an accepted catalog
lists the CVE again.

File: state/kev/withdrawn.json, {"withdrawn": {CVE: {"source", "at",
"accepted": [project, ...]}}}. ``accepted`` lists the projects whose
operator accepted the withdrawal with `security resume`; they are not held
for it again.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths
from boxmunge.fs_nofollow import read_text_nofollow


class KevWithdrawalsError(Exception):
    """The withdrawals file cannot be read or written; names the file."""


@dataclass(frozen=True)
class Withdrawal:
    source: str                # the KEV source whose catalog dropped the CVE
    at: str                    # when the refresh recorded it
    accepted: frozenset[str]   # projects whose `security resume` accepted it


def _entries(paths: BoxPaths) -> dict[str, dict[str, Any]]:
    path = paths.kev_withdrawn
    if not path.exists():
        return {}
    try:
        entries = json.loads(read_text_nofollow(path))["withdrawn"]
        for entry in entries.values():
            if not isinstance(entry["source"], str) or not isinstance(entry["at"], str):
                raise ValueError("an entry has no source or time")
            if not all(isinstance(p, str) for p in entry.get("accepted", [])):
                raise ValueError("an entry's accepted list is not project names")
        return entries
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise KevWithdrawalsError(f"cannot read the KEV withdrawals {path}: {e!r}") from e


def _write(paths: BoxPaths, entries: dict[str, dict[str, Any]]) -> None:
    try:
        atomic_write_text(paths.kev_withdrawn,
                          json.dumps({"withdrawn": dict(sorted(entries.items()))}, indent=2) + "\n")
    except OSError as e:
        raise KevWithdrawalsError(
            f"cannot write the KEV withdrawals {paths.kev_withdrawn}: {e}") from e


def load_withdrawals(paths: BoxPaths) -> dict[str, Withdrawal]:
    """{CVE: its withdrawal}; empty if none was recorded. Raises
    KevWithdrawalsError."""
    return {cve: Withdrawal(e["source"], e["at"], frozenset(e.get("accepted", [])))
            for cve, e in _entries(paths).items()}


def record_withdrawals(
    paths: BoxPaths, source: str, withdrawn: Iterable[str], listed: Iterable[str],
) -> None:
    """Add ``withdrawn`` (from ``source``) and drop every CVE the accepted
    catalog lists again (``listed``). Raises KevWithdrawalsError."""
    entries = _entries(paths)
    now = datetime.now(timezone.utc).isoformat()
    for cve in withdrawn:
        entries.setdefault(cve, {"source": source, "at": now})
    listed = set(listed)
    kept = {cve: e for cve, e in entries.items() if cve not in listed}
    if not kept and not paths.kev_withdrawn.exists():
        return
    _write(paths, kept)


def accept_withdrawals(paths: BoxPaths, project: str, cves: Iterable[str]) -> list[str]:
    """Record that ``project``'s operator accepted the withdrawal of each of
    ``cves`` that is recorded (`security resume`); return those, sorted.
    Raises KevWithdrawalsError."""
    entries = _entries(paths)
    accepted = sorted(c for c in set(cves) if c in entries
                      and project not in entries[c].get("accepted", []))
    for cve in accepted:
        entries[cve]["accepted"] = sorted({*entries[cve].get("accepted", []), project})
    if accepted:
        _write(paths, entries)
    return accepted
