# SPDX-License-Identifier: Apache-2.0
"""Observe actions over logs: project.logs (containers) and oplog.query
(the structured operational log)."""
from __future__ import annotations

import json
from typing import Any

from boxmunge.api.actions._common import PROJECT_PARAM, TAIL_MAX, deployed_project
from boxmunge.api.context import ActionContext
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Action
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import INTEGER, NULLABLE_STRING, STRING, arr, enum, obj
from boxmunge.commands.log_cmd import filter_log_entries
from boxmunge.docker import DockerError
from boxmunge.manifest import load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

LOGS_TAIL_DEFAULT = 100
OPLOG_TAIL_DEFAULT = 50
SERVICE_PATTERN = "[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}"
LEVELS = ("debug", "info", "warn", "error")
_ENTRY_KEYS = frozenset({"ts", "level", "component", "msg"})
SINCE_MAX_DAYS = 3650
_MINUTES_PER = {"m": 1, "h": 60, "d": 24 * 60}


def _tail(default: int) -> dict[str, Any]:
    return {"type": "integer", "minimum": 1, "maximum": TAIL_MAX,
            "description": f"How many of the newest lines to return. Default {default}."}


LOGS_PARAMS = obj({
    "project": PROJECT_PARAM,
    "service": {"type": "string", "pattern": SERVICE_PATTERN,
                "description": "One service from the manifest. Omit for every service."},
    "tail": _tail(LOGS_TAIL_DEFAULT),
}, optional=("service", "tail"))

LOGS_RESULT = obj({
    "project": STRING, "service": NULLABLE_STRING, "tail": INTEGER, "lines": arr(STRING),
})

OPLOG_PARAMS = obj({
    "project": PROJECT_PARAM,
    "component": {"type": "string", "pattern": "[a-z0-9_-]{1,64}",
                  "description": "Only entries from this component: deploy, backup, health..."},
    "level": {**enum(*LEVELS), "description": "Only entries at exactly this level."},
    "since": {"type": "string", "pattern": "[0-9]{1,6}[mhd]",
              "description": f"Only entries newer than this: 30m, 6h, 7d. At most "
                             f"{SINCE_MAX_DAYS} days."},
    "tail": _tail(OPLOG_TAIL_DEFAULT),
}, optional=("project", "component", "level", "since", "tail"))

OPLOG_ENTRY = obj({
    "ts": STRING, "level": STRING, "component": STRING, "project": NULLABLE_STRING,
    "msg": STRING,
    "detail": {"type": ["string", "null"],
               "description": "The entry's detail object as compact JSON, or null."},
})


def _project_logs(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    name = params["project"]
    deployed_project(ctx.paths, name)
    service = params.get("service")
    tail = params.get("tail", LOGS_TAIL_DEFAULT)
    if service is not None:
        services = load_manifest(ctx.paths.project_manifest(name)).get("services") or {}
        if service not in services:
            raise ActionError(ErrorCode.NOT_FOUND,
                              f"Project '{name}' has no service '{service}'. Its services: "
                              f"{', '.join(sorted(services)) or 'none'}.")
    try:
        output = ctx.host.container_logs(name, service, tail)
    except DockerError as e:
        raise ActionError(ErrorCode.UNAVAILABLE,
                          f"Container logs for '{name}' could not be read: {e}") from e
    return {"project": name, "service": service, "tail": tail, "lines": output.splitlines()}


def _oplog_query(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    since = params.get("since")
    if since is not None and int(since[:-1]) * _MINUTES_PER[since[-1]] > SINCE_MAX_DAYS * 24 * 60:
        raise ActionError(ErrorCode.INVALID_PARAMS,
                          f"since may reach back at most {SINCE_MAX_DAYS} days "
                          f"({SINCE_MAX_DAYS}d); {since!r} is further.")
    entries = filter_log_entries(
        _entries(ctx.paths),
        project=params.get("project"), component=params.get("component"),
        level=params.get("level"), since=params.get("since"),
        tail=params.get("tail", OPLOG_TAIL_DEFAULT),
    )
    return {"entries": [_entry_view(entry) for entry in entries]}


def _entries(paths: BoxPaths) -> list[dict[str, Any]]:
    """Every operational log entry. Unlike the CLI's `log`, a line that is
    not an entry (torn by a crash, or hand-edited) fails the query, naming
    the line, rather than vanishing from what a dashboard shows."""
    path = paths.log_file
    if not path.exists():
        return []
    entries = []
    with path.open() as log:
        for lineno, line in enumerate(log, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError as e:
                raise StateError(f"{path}:{lineno} is not JSON ({e}); repair or remove "
                                 f"that line") from e
            if not isinstance(entry, dict) or not _ENTRY_KEYS <= entry.keys():
                raise StateError(f"{path}:{lineno} is not an operational log entry: "
                                 f"{line.strip()[:200]}")
            entries.append(entry)
    return entries


def _entry_view(entry: dict[str, Any]) -> dict[str, Any]:
    detail = entry.get("detail")
    return {
        "ts": entry["ts"], "level": entry["level"], "component": entry["component"],
        "project": entry.get("project"), "msg": entry["msg"],
        "detail": None if detail is None else json.dumps(detail, sort_keys=True, default=str),
    }


ACTIONS = (
    Action(
        name="project.logs", tier=Tier.OBSERVE,
        summary="The newest lines of a project's container logs, for one service or all.",
        params=LOGS_PARAMS, result=LOGS_RESULT, handler=_project_logs,
        cli="logs", mcp=True,
    ),
    Action(
        name="oplog.query", tier=Tier.OBSERVE,
        summary="Entries from the operational log (deploys, backups, health, CVE "
                "decisions), filtered.",
        params=OPLOG_PARAMS, result=obj({"entries": arr(OPLOG_ENTRY)}),
        handler=_oplog_query, cli="log", mcp=True,
    ),
)
