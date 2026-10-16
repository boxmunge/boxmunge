# SPDX-License-Identifier: Apache-2.0
"""Observe action over backups: backups.list."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from boxmunge.api.actions._common import PROJECT_PARAM, existing_project
from boxmunge.api.context import ActionContext
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Action
from boxmunge.api.schema import INTEGER, NULLABLE_STRING, STRING, arr, enum, nullable, obj
from boxmunge.backup import BackupKind, parse_snapshot
from boxmunge.commands.backup_cmd import list_snapshots

SNAPSHOT = obj({
    "name": STRING,
    "kind": nullable(enum(*(kind.value for kind in BackupKind))),
    "taken_at": NULLABLE_STRING,
    "size": INTEGER,
})


def _backups_list(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    name = params["project"]
    existing_project(ctx.paths, name)
    snapshots = []
    for path in list_snapshots(ctx.paths, name):
        parsed = parse_snapshot(path, name)
        snapshots.append({
            "name": path.name,
            "kind": parsed[1].value if parsed else None,
            "taken_at": _iso(parsed[0]) if parsed else None,
            "size": path.stat().st_size,
        })
    return {"project": name, "snapshots": snapshots}


def _iso(timestamp: str) -> str:
    """'2026-10-14T020000' (a snapshot name's timestamp, UTC) to ISO 8601."""
    moment = datetime.strptime(timestamp, "%Y-%m-%dT%H%M%S").replace(tzinfo=timezone.utc)
    return moment.isoformat().replace("+00:00", "Z")


ACTIONS = (
    Action(
        name="backups.list", tier=Tier.OBSERVE,
        summary="A project's encrypted backup snapshots, newest first, with kind and time.",
        params=obj({"project": PROJECT_PARAM}),
        result=obj({"project": STRING, "snapshots": arr(SNAPSHOT)}),
        handler=_backups_list, mcp=True,
    ),
)
