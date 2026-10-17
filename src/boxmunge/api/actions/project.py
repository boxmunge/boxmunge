# SPDX-License-Identifier: Apache-2.0
"""Observe actions about one project: project.get, project.health, inbox.list."""
from __future__ import annotations

from typing import Any

from boxmunge.api.actions._common import (
    PROJECT_PARAM, QUARANTINE_SCHEMA, deployed_project, project_not_found, project_path,
    quarantine_view,
)
from boxmunge.api.context import ActionContext
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Action
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import (
    BOOLEAN, INTEGER, NULLABLE_INTEGER, NULLABLE_STRING, STRING, arr, enum, nullable, obj,
)
from boxmunge.api.timefmt import NULLABLE_TIMESTAMP, TIMESTAMP, utc_timestamp
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.commands.inbox_cmd import collect_inbox
from boxmunge.commands.status import HEALTH_STATES
from boxmunge.cve.quarantine import read_quarantine_state
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.legacy_stage import EvidenceError, cannot_tell, evidence, legacy_stage
from boxmunge.pause import read_paused_state
from boxmunge.project_registry import is_registered
from boxmunge.paths import BoxPaths
from boxmunge.release_txn import ABANDON_PHASES, PHASES, SOURCES, load_txn
from boxmunge.staged_release import STATES as STAGING_STATES, SlotError, load_slot
from boxmunge.state import StateError, read_state

LIFECYCLES = ("registered", "pre_registered", "quarantined", "paused", "monitor_stopped",
              "running")

INSTALL_VIEW = nullable(obj({"id": STRING, "source": enum(*SOURCES), "ref": STRING,
                             "phase": enum(*PHASES, *ABANDON_PHASES)}))
LEGACY_VIEW = nullable(obj({"kind": enum("bundle", "git", "leftover"),
                            "evidence": nullable(enum("untouched", "recreated", "unknown"))}))

PROJECT_VIEW = obj({
    "project": STRING,
    "lifecycle": enum(*LIFECYCLES),
    "health": obj({
        "status": enum(*HEALTH_STATES),
        "last_check": NULLABLE_TIMESTAMP,
        "consecutive_failures": NULLABLE_INTEGER,
        "failure_reason": NULLABLE_STRING,
    }),
    "deploy": obj({
        "current_ref": NULLABLE_STRING,
        "deployed_at": NULLABLE_TIMESTAMP,
        "history": arr(obj({
            "ref": STRING, "deployed_at": NULLABLE_TIMESTAMP, "snapshot": NULLABLE_STRING,
        })),
    }),
    "staging": obj({"active": BOOLEAN, "id": NULLABLE_STRING, "ref": NULLABLE_STRING,
                    "state": nullable(enum(*STAGING_STATES))}),
    "paused": nullable(obj({"paused_at": TIMESTAMP, "reason": NULLABLE_STRING})),
    "quarantine": nullable(QUARANTINE_SCHEMA),
    "install": INSTALL_VIEW,
    "legacy_stage": LEGACY_VIEW,
})

CHECK_RESULT = obj({
    "project": STRING,
    "exit_code": INTEGER,
    "status": enum("ok", "warning", "critical", "unknown"),
    "smoke": obj({"status": enum("ok", "warning", "critical"), "message": STRING}),
}, optional=("smoke",))

BUNDLE = obj({"name": STRING, "project": STRING, "size": INTEGER, "mtime": TIMESTAMP})


def _install_view(paths: BoxPaths, name: str) -> dict[str, Any] | None:
    try:
        txn = load_txn(paths, name)
    except ReleaseStateError as e:
        raise StateError(f"The install record of {name} is unreadable: {e}") from e
    return None if txn is None else {"id": txn.id, "source": txn.source, "ref": txn.ref,
                                     "phase": txn.phase}


def _legacy_view(paths: BoxPaths, name: str) -> dict[str, Any] | None:
    """A stage left by 0.10.1. Its evidence asks Docker (and git) what
    production runs; when that cannot be read the stage is still reported,
    as "unknown". A detection that cannot tell is not a "no stage"."""
    try:
        stage = legacy_stage(paths, name)
    except OSError as e:
        raise StateError(cannot_tell(name, e)) from e
    if stage is None:
        return None
    if stage.kind == "leftover":
        return {"kind": stage.kind, "evidence": None}
    try:
        found = evidence(paths, name, stage).classification
    except (EvidenceError, OSError):
        found = "unknown"
    return {"kind": stage.kind, "evidence": found}


def _project_get(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    name = params["project"]
    paths = ctx.paths
    project_dir = project_path(paths, name)
    has_dir = project_dir.is_dir()
    if not has_dir and not is_registered(name, paths):
        raise project_not_found(name)
    deployed = has_dir and (project_dir / "manifest.yml").exists()
    deploy = read_state(paths.project_deploy_state(name))
    health = read_state(paths.project_health_state(name))
    try:
        slot = load_slot(paths, name)
    except SlotError as e:
        raise StateError(f"The staged release of {name} is unreadable: {e}") from e
    paused = read_paused_state(name, paths)
    if paused is not None and not isinstance(paused.get("paused_at"), str):
        raise StateError(f"Paused state {paths.project_paused_state(name)} has no paused_at "
                         f"timestamp; resume the project or rewrite the file.")
    quarantine = read_quarantine_state(name, paths)
    health_status = health.get("status", "unknown")
    if health_status not in HEALTH_STATES:
        raise StateError(f"Health state {paths.project_health_state(name)} has the status "
                         f"{health_status!r}; boxmunge writes one of {', '.join(HEALTH_STATES)}")
    deploy_file = paths.project_deploy_state(name)
    return {
        "project": name,
        "lifecycle": _lifecycle(name, paths, has_dir=has_dir, deployed=deployed,
                                paused=paused is not None,
                                quarantined=quarantine is not None),
        "health": {
            "status": health_status,
            "last_check": utc_timestamp(health.get("last_check"),
                                        f"{paths.project_health_state(name)} last_check"),
            "consecutive_failures": health.get("consecutive_failures"),
            "failure_reason": health.get("failure_reason") or None,
        },
        "deploy": {
            "current_ref": deploy.get("current_ref"),
            "deployed_at": utc_timestamp(deploy.get("deployed_at"), f"{deploy_file} deployed_at"),
            "history": [
                {"ref": entry["ref"],
                 "deployed_at": utc_timestamp(entry.get("deployed_at") or None,
                                              f"{deploy_file} history deployed_at"),
                 "snapshot": entry.get("snapshot") or None}
                for entry in deploy.get("history", [])
            ],
        },
        "staging": {"active": slot is not None, "id": slot.id if slot else None,
                    "ref": slot.ref if slot else None, "state": slot.state if slot else None},
        "paused": None if paused is None else {
            "paused_at": utc_timestamp(paused["paused_at"],
                                       f"{paths.project_paused_state(name)} paused_at"),
            "reason": paused.get("reason")},
        "quarantine": None if quarantine is None else quarantine_view(
            quarantine, paths.project_quarantine_state(name)),
        "install": _install_view(paths, name),
        "legacy_stage": _legacy_view(paths, name),
    }


def _lifecycle(name: str, paths: BoxPaths, *, has_dir: bool, deployed: bool, paused: bool,
               quarantined: bool) -> str:
    """Quarantine wins over pause, as in lifecycle.is_blocked. "registered"
    is a name project-add recorded before any directory exists;
    "pre_registered" has a directory (secrets set) but no manifest yet."""
    if not has_dir:
        return "registered"
    if not deployed:
        return "pre_registered"
    if quarantined:
        return "quarantined"
    if paused:
        return "paused"
    if is_monitor_stopped(name, paths):
        return "monitor_stopped"
    return "running"


def _project_health(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    name = params["project"]
    deployed_project(ctx.paths, name)
    report = ctx.host.project_check(name)
    if "error" in report:
        raise ActionError(ErrorCode.FAILED, report["error"])
    return report


def _inbox_list(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    return {"bundles": collect_inbox(ctx.paths, params.get("project"))}


ACTIONS = (
    Action(
        name="project.get", tier=Tier.OBSERVE,
        summary="One project: lifecycle state, health, deploy history, staging, "
                "pause and quarantine.",
        params=obj({"project": PROJECT_PARAM}), result=PROJECT_VIEW,
        handler=_project_get, mcp=True,
    ),
    Action(
        name="project.health", tier=Tier.OBSERVE,
        summary="Run the project's smoke checks now and report the worst result.",
        params=obj({"project": PROJECT_PARAM}), result=CHECK_RESULT,
        handler=_project_health, cli="check", mcp=True,
    ),
    Action(
        name="inbox.list", tier=Tier.OBSERVE,
        summary="Bundles uploaded to the inbox and not yet deployed, newest first.",
        params=obj({"project": PROJECT_PARAM}, optional=("project",)),
        result=obj({"bundles": arr(BUNDLE)}), handler=_inbox_list,
        cli="inbox", mcp=True,
    ),
)
