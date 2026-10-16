# SPDX-License-Identifier: Apache-2.0
"""Tell the operator, once, that a git project's manifest has an old schema.

A git project's manifest.yml links into its checkout. The upgrade never
rewrites it (see manifest.write_manifest), and every reader migrates it in
memory instead, so nothing breaks. But the file in the repository stays at
the old schema until somebody updates it there, which only the operator can
do. They are told once per (repository schema, current schema) pair: a
record under state/manifest-schema/ remembers what was said, and is written
only when the alert was delivered, so an undelivered one is retried on the
next upgrade.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from boxmunge.fileutil import atomic_write_text
from boxmunge.log import log_error, log_warning
from boxmunge.manifest import CURRENT_SCHEMA_VERSION
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths


def _record(written: int) -> dict[str, int]:
    return {"repository_schema": written, "current_schema": CURRENT_SCHEMA_VERSION}


def _already_alerted(paths: BoxPaths, project: str, written: int) -> bool:
    path = paths.manifest_schema_alert_state(project)
    if not path.exists():
        return False
    try:
        recorded = json.loads(path.read_text())
        if not isinstance(recorded, dict):
            raise ValueError("not a JSON object")
    except (OSError, UnicodeDecodeError, ValueError) as e:
        log_error("upgrade", f"{path} is unreadable ({e}); alerting again and "
                  f"replacing it", paths, project=project)
        return False
    return {k: recorded.get(k) for k in _record(written)} == _record(written)


def _message(project: str, written: int) -> str:
    return (f"{project}: the repository's manifest.yml uses schema {written}; "
            f"boxmunge migrates it in memory to schema {CURRENT_SCHEMA_VERSION}. "
            f"Update it in the repository (set schema_version: "
            f"{CURRENT_SCHEMA_VERSION}) and deploy.")


def alert_outdated_repository_manifest(paths: BoxPaths, project: str, written: int) -> None:
    """Log and alert, unless this project's (written, current) schema pair
    has been alerted already."""
    if _already_alerted(paths, project, written):
        return
    message = _message(project, written)
    log_warning("upgrade", message, paths, project=project)
    if not notify(paths, f"{project}: update manifest.yml in the repository",
                  message, component="upgrade", project=project):
        return
    record = paths.manifest_schema_alert_state(project)
    try:
        atomic_write_text(record, json.dumps(
            {**_record(written), "alerted_at": datetime.now(timezone.utc).isoformat()}) + "\n")
    except OSError as e:
        # Not worth rolling the upgrade back for: the alert went out, and the
        # cost is that the next upgrade sends it again.
        log_error("upgrade", f"Cannot record {record} ({e}); the alert will "
                  f"repeat on the next upgrade", paths, project=project)
