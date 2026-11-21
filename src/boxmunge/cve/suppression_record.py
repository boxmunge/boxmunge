# SPDX-License-Identifier: Apache-2.0
"""The suppression notice record: ``state/cve/suppression-notices.json``.

``{"warned": [{"cve_id", "scope", "project", "until", "warned_at"}],
"pending_host_expiries": [{"cve_id", "until"}]}``; ``project`` is "" for a
host suppression, ``until`` a YYYY-MM-DD date, ``warned_at`` ISO 8601 UTC.

``warned``: a warning is sent once per key (CVE, scope, project, until),
and recorded only once delivered. Extending a suppression changes its
``until`` and so its key: the new date is warned again when it nears. An
entry is pruned once its ``until`` has passed.

``pending_host_expiries``: a host suppression whose expiry a partial run (a
single-project scan, a KEV watch tick) detected, or whose expiry alert was
not delivered. The next full fleet run alerts it with every project judged.

Read-modify-write is under ``record_lock``: a single-project scan holds only
its project's lock, so two can run at once.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime

from boxmunge.cve.suppressions import SCOPE_HOST, Suppression
from boxmunge.fileutil import atomic_write_text, exclusive_lock
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

Key = tuple[str, str, str, str]   # (CVE id, scope, project or "", until)
HostKey = tuple[str, str]         # (CVE id, until)


def warned_key(sup: Suppression, project: str) -> Key:
    """The key a warning for ``sup``, judged by ``project``'s scan, is sent
    once for. A host suppression is one key for the whole fleet."""
    owner = "" if sup.scope == SCOPE_HOST else project
    return (sup.cve_id, sup.scope, owner, sup.until.isoformat())


def host_key(sup: Suppression) -> HostKey:
    return (sup.cve_id, sup.until.isoformat())


@dataclass
class NoticeRecord:
    warned: dict[Key, datetime] = field(default_factory=dict)
    pending: set[HostKey] = field(default_factory=set)


def repair_hint(paths: BoxPaths) -> str:
    return (f"remove {paths.suppression_notices} to start afresh (warnings of "
            f"suppressions still in their window are then sent again)")


@contextmanager
def record_lock(paths: BoxPaths) -> Iterator[None]:
    with exclusive_lock(paths.suppression_notices.with_name(".suppression-notices.lock")):
        yield


def _strings(item: dict, *names: str) -> tuple[str, ...]:
    values = tuple(item[n] for n in names)
    if not all(isinstance(v, str) for v in values):
        raise ValueError(f"an entry is not all strings: {item!r}")
    date.fromisoformat(item["until"])
    return values


def read_record(paths: BoxPaths) -> NoticeRecord:
    """The record (empty before the first notice). Raises StateError naming
    the file. Hold ``record_lock`` across a read and its write."""
    path = paths.suppression_notices
    try:
        raw = read_text_nofollow_or_none(path)
        if raw is None:
            return NoticeRecord()
        data = json.loads(raw)
        record = NoticeRecord()
        for item in data["warned"]:
            key = _strings(item, "cve_id", "scope", "project", "until")
            when = datetime.fromisoformat(item["warned_at"])
            if when.tzinfo is None:
                raise ValueError(f"warned_at {item['warned_at']!r} has no timezone")
            record.warned[key] = when  # type: ignore[index]
        for item in data["pending_host_expiries"]:
            record.pending.add(_strings(item, "cve_id", "until"))  # type: ignore[arg-type]
        return record
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise StateError(f"cannot read the suppression notice record {path}: {e!r}") from e


def write_record(paths: BoxPaths, record: NoticeRecord, today: date) -> None:
    """Write the record atomically, without warned keys whose ``until`` has
    passed. Raises StateError."""
    path = paths.suppression_notices
    body = {
        "warned": [{"cve_id": k[0], "scope": k[1], "project": k[2], "until": k[3],
                    "warned_at": when.isoformat()}
                   for k, when in sorted(record.warned.items())
                   if date.fromisoformat(k[3]) > today],
        "pending_host_expiries": [{"cve_id": c, "until": u} for c, u in sorted(record.pending)],
    }
    try:
        # atomic_write_text creates state/cve/ as deploy's when run as root.
        atomic_write_text(path, json.dumps(body, indent=2) + "\n")
    except OSError as e:
        raise StateError(f"cannot write the suppression notice record {path}: {e}") from e
