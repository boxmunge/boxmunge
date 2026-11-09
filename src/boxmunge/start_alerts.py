# SPDX-License-Identifier: Apache-2.0
"""How often a refused start alerts (compose_guard)."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import mkdir_p_deploy

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# A persistently tampered project is checked on every timer tick (container
# update daily, health every few minutes); without this an operator is paged
# on each one. The refusal is always logged; the alert repeats only this
# often per project and reason.
_ALERT_INTERVAL = timedelta(hours=24)


def alerted_recently(paths: BoxPaths, project_name: str, reason: str, now: datetime) -> bool:
    path = paths.state / "start-refused" / f"{project_name}.json"
    key = hashlib.sha256(reason.encode()).hexdigest()[:16]
    try:
        doc = json.loads(path.read_text())
        last = datetime.fromisoformat(doc[key])
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return last.tzinfo is not None and now - last < _ALERT_INTERVAL


def record(paths: BoxPaths, project_name: str, reason: str, now: datetime) -> None:
    path = paths.state / "start-refused" / f"{project_name}.json"
    key = hashlib.sha256(reason.encode()).hexdigest()[:16]
    mkdir_p_deploy(path.parent)
    try:
        doc = json.loads(path.read_text())
        if not isinstance(doc, dict):
            doc = {}
    except (OSError, ValueError):
        doc = {}
    doc[key] = now.isoformat()
    atomic_write_text(path, json.dumps(doc) + "\n")
