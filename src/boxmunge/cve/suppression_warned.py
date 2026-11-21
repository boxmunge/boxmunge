# SPDX-License-Identifier: Apache-2.0
"""Which suppression expiry warnings were sent: ``state/cve/suppression-warnings.json``.

``{"warned": [{"cve_id", "scope", "project", "until", "warned_at"}]}``;
``project`` is "" for a host suppression, ``until`` a YYYY-MM-DD date,
``warned_at`` ISO 8601 UTC.

A warning is sent once per key (CVE, scope, project, until). Extending a
suppression changes its ``until`` and so its key: the new date is warned
again when it nears. An entry is pruned once its ``until`` has passed (the
suppression has expired; the expiry alert is not keyed here).
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import date, datetime

from boxmunge.cve.suppressions import SCOPE_HOST, Suppression
from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

Key = tuple[str, str, str, str]   # (CVE id, scope, project or "", until)


def warned_key(sup: Suppression, project: str) -> Key:
    """The key a warning for ``sup``, judged by ``project``'s scan, is sent
    once for. A host suppression is one key for the whole fleet."""
    owner = "" if sup.scope == SCOPE_HOST else project
    return (sup.cve_id, sup.scope, owner, sup.until.isoformat())


def _repair(path) -> str:
    return (f"remove {path} to start afresh (the warnings of suppressions still "
            f"in their window are then sent again)")


def read_warned(paths: BoxPaths) -> dict[Key, datetime]:
    """Each key warned, with when. Raises StateError naming the file."""
    path = paths.suppression_warnings
    try:
        raw = read_text_nofollow_or_none(path)
        if raw is None:
            return {}
        out: dict[Key, datetime] = {}
        for item in json.loads(raw)["warned"]:
            key = (item["cve_id"], item["scope"], item["project"], item["until"])
            if not all(isinstance(k, str) for k in key):
                raise ValueError(f"an entry is not four strings: {item!r}")
            date.fromisoformat(key[3])
            when = datetime.fromisoformat(item["warned_at"])
            if when.tzinfo is None:
                raise ValueError(f"warned_at {item['warned_at']!r} has no timezone")
            out[key] = when
        return out
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise StateError(
            f"cannot read the suppression warning record {path}: {e!r}; {_repair(path)}"
        ) from e


def write_warned(paths: BoxPaths, warned: Mapping[Key, datetime], today: date) -> None:
    """Write the record atomically, without the keys whose ``until`` has
    passed. Raises StateError."""
    path = paths.suppression_warnings
    rows = [{"cve_id": k[0], "scope": k[1], "project": k[2], "until": k[3],
             "warned_at": when.isoformat()}
            for k, when in sorted(warned.items()) if date.fromisoformat(k[3]) > today]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, json.dumps({"warned": rows}, indent=2) + "\n")
    except OSError as e:
        raise StateError(f"cannot write the suppression warning record {path}: {e}") from e
