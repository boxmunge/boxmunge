# SPDX-License-Identifier: Apache-2.0
"""How often an alert repeats: a refused start (compose_guard), and the
host config's wrong settings (host_config_alert)."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import mkdir_p_deploy, read_text_nofollow
from boxmunge.log import log_warning

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# A persistently tampered project is checked on every timer tick (container
# update daily, health every few minutes); without this an operator is paged
# on each one. The refusal is always logged; a delivered alert repeats only
# this often per project and reason. The caller records an alert only once
# notify says it was delivered, so an undelivered one is tried again.
_ALERT_INTERVAL = timedelta(hours=24)


def alerted_recently(paths: BoxPaths, project_name: str, reason: str, now: datetime) -> bool:
    path = paths.state / "start-refused" / f"{project_name}.json"
    key = hashlib.sha256(reason.encode()).hexdigest()[:16]
    try:
        doc = json.loads(read_text_nofollow(path))
        last = datetime.fromisoformat(doc[key])
    except (OSError, ValueError, KeyError, TypeError):
        return False
    # A time ahead of now was not written by this clock (a corrected clock,
    # an edited file): it would silence the alert until it passed, so it
    # counts for nothing.
    return last.tzinfo is not None and timedelta(0) <= now - last < _ALERT_INTERVAL


def record(paths: BoxPaths, project_name: str, reason: str, now: datetime) -> None:
    path = paths.state / "start-refused" / f"{project_name}.json"
    key = hashlib.sha256(reason.encode()).hexdigest()[:16]
    mkdir_p_deploy(path.parent)
    try:
        doc = json.loads(read_text_nofollow(path))
        if not isinstance(doc, dict):
            doc = {}
    except (OSError, ValueError):
        doc = {}
    doc[key] = now.isoformat()
    atomic_write_text(path, json.dumps(doc) + "\n")


def record_or_warn(paths: BoxPaths, project_name: str, reason: str, now: datetime,
                   component: str) -> None:
    """record(), for a caller that must carry on whatever becomes of the
    record: the alert is sent by then, and a start, an upgrade or a
    rollback must not fail because its pacing could not be written. Without
    the record the alert simply repeats at the next run."""
    try:
        record(paths, project_name, reason, now)
    except OSError as e:
        log_warning(component, f"Cannot record that the alert was sent "
                    f"({paths.state / 'start-refused' / (project_name + '.json')}: {e}); "
                    f"it repeats at the next run until this is fixed", paths)
