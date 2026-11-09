# SPDX-License-Identifier: Apache-2.0
"""CVEs a KEV refresh withdrew from the catalog, kept until it lists them again.

One source can drop an entry (up to KEV_MAX_REMOVALS per refresh are
accepted), and under balanced the drop alone would lift a quarantine held
for it. The refresh records each withdrawal here before it caches the new
catalog, so every later scan and the deploy gate can hold such a quarantine
until `security resume` accepts it, however many runs later that is
(commands/kev_withdrawal.py). An entry is removed when an accepted catalog
lists the CVE again.

File: state/kev/withdrawn.json, {"withdrawn": {CVE: {"source", "at"}}}.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone

from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths


class KevWithdrawalsError(Exception):
    """The withdrawals file cannot be read or written; names the file."""


def _entries(paths: BoxPaths) -> dict[str, dict[str, str]]:
    path = paths.kev_withdrawn
    if not path.exists():
        return {}
    try:
        entries = json.loads(path.read_text())["withdrawn"]
        if not all(isinstance(e.get("source"), str) for e in entries.values()):
            raise ValueError("an entry has no source")
        return entries
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise KevWithdrawalsError(f"cannot read the KEV withdrawals {path}: {e!r}") from e


def load_withdrawals(paths: BoxPaths) -> dict[str, tuple[str, str]]:
    """{CVE: (source that withdrew it, when)}; empty if none was recorded.
    Raises KevWithdrawalsError."""
    return {cve: (entry["source"], str(entry.get("at"))) for cve, entry in _entries(paths).items()}


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
    kept = {cve: e for cve, e in sorted(entries.items()) if cve not in listed}
    if kept == entries and not paths.kev_withdrawn.exists() and not kept:
        return
    try:
        atomic_write_text(paths.kev_withdrawn, json.dumps({"withdrawn": kept}, indent=2) + "\n")
    except OSError as e:
        raise KevWithdrawalsError(
            f"cannot write the KEV withdrawals {paths.kev_withdrawn}: {e}") from e
