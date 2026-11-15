# SPDX-License-Identifier: Apache-2.0
"""Runtime actions on a project, each a job over the core its CLI command
runs: project.pause, project.resume, project.backup and project.restore
(operate), and project.recover and project.abandon_install (govern).

recover restarts a build the health monitor stopped, and abandon_install
puts back the code of an open install: both are ways out the operator
takes after looking at why, so they are whole govern actions no agent
may run. The flags that skip a safety snapshot or resume's security
checks carry x-tier govern (_operate).

The backup action does not end upgrade probation: only the operator's
interactive `backup` does, as it is the operator looking at the box.
"""
from __future__ import annotations

from typing import Any

from boxmunge.api.actions._operate import PROJECT, operate_job, run_core
from boxmunge.api.context import ActionContext
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Action, Handler
from boxmunge.api.schema import BOOLEAN, STRING, obj
from boxmunge.commands.backup_cmd import snapshot_locked
from boxmunge.commands.install_abandon import abandon_locked
from boxmunge.commands.pause_cmd import pause_locked
from boxmunge.commands.recover_cmd import recover_locked
from boxmunge.commands.restore import restore_locked
from boxmunge.commands.resume_cmd import alert_smoke_failed, hand_to_deploy_locked, resume_locked

NO_RESULT = obj({})
# Without the pause snapshot, a deploy that ends the pause cannot roll back the data.
PAUSE_NO_SNAPSHOT = {
    **BOOLEAN, "x-tier": "govern",
    "description": "Pause without the snapshot a deploy that ends the pause would roll back "
                   "to (--no-snapshot).",
}
SKIP_SECURITY_CHECKS = {
    **BOOLEAN, "x-tier": "govern",
    "description": "Start without pulling the current images first "
                   "(--skip-security-checks).",
}
NO_SAFETY_SNAPSHOT = {
    **BOOLEAN, "x-tier": "govern",
    "description": "Restore without first snapshotting the data it overwrites "
                   "(--no-safety-snapshot).",
}


def _pause(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    run_core("pause", lambda: pause_locked(
        params["project"], ctx.paths, params.get("reason"),
        no_snapshot=params.get("no_snapshot", False)))
    return {}


def _resume(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    project = params["project"]
    if params.get("no_start", False):
        run_core("resume", lambda: hand_to_deploy_locked(project, ctx.paths))
        return {}
    rc, smoke_failure = resume_locked(project, ctx.paths,
                                      params.get("skip_security_checks", False))
    if smoke_failure is not None:
        if ctx.after_release is None:
            raise RuntimeError("project.resume ran outside the job worker, which alone "
                               "sets after_release for the smoke alert")
        # Pushover is a network call: it waits until the project lock is released.
        ctx.after_release(lambda: alert_smoke_failed(project, ctx.paths, smoke_failure))
    run_core("resume", lambda: rc)
    return {}


def _resume_check(params: dict[str, Any]) -> str | None:
    if params.get("no_start", False) and params.get("skip_security_checks", False):
        return "no_start starts nothing, so it takes no skip_security_checks"
    return None


def _backup(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    project = params["project"]
    result = snapshot_locked(project, ctx.paths)
    run_core("backup", lambda: result.rc)
    if result.snapshot is None:
        why = result.cause or ("none was due: its backup type is none, or it is "
                               "CVE-quarantined")
        raise RuntimeError(f"The backup of {project} wrote no snapshot: {why}.")
    return {"snapshot": result.snapshot.name}


def _restore(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    run_core("restore", lambda: restore_locked(
        params["project"], ctx.paths, params.get("snapshot"),
        safety_snapshot=not params.get("no_safety_snapshot", False)))
    return {}


def _recover(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    run_core("recover", lambda: recover_locked(params["project"], ctx.paths))
    return {}


def _abandon(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    run_core("prod-deploy", lambda: abandon_locked(params["project"], ctx.paths))
    return {}


def _govern_job(name: str, summary: str, handler: Handler, cli: str) -> Action:
    """A govern action run as a job under the project lock, closed to agents."""
    return Action(name=name, tier=Tier.GOVERN, summary=summary,
                  params=obj({"project": PROJECT}), result=NO_RESULT, handler=handler,
                  locks=("project",), job=True, cli=cli)


ACTIONS = (
    operate_job(
        "project.pause", "Stop a project behind its maintenance page (pause).",
        params={
            "reason": {"type": "string", "minLength": 1, "maxLength": 500,
                       "description": "Why it is paused; logged (--reason)."},
            "no_snapshot": PAUSE_NO_SNAPSHOT,
        },
        result=NO_RESULT, handler=_pause, cli="pause",
    ),
    operate_job(
        "project.resume", "Bring a paused project back online (resume).",
        params={
            "skip_security_checks": SKIP_SECURITY_CHECKS,
            "no_start": {**BOOLEAN, "description": "Start nothing: hand the pause to the "
                                                   "next deploy (--no-start)."},
        },
        result=NO_RESULT, handler=_resume, cli="resume", param_check=_resume_check,
    ),
    operate_job(
        "project.backup", "Take an encrypted snapshot of a project's data (backup).",
        params={}, result=obj({"snapshot": STRING}), handler=_backup, cli="backup",
    ),
    operate_job(
        "project.restore", "Restore a project's data from a snapshot (restore).",
        params={
            "snapshot": {"type": "string", "minLength": 1, "maxLength": 200,
                         "description": "The snapshot's file name, as backups.list gives "
                                        "it; the newest when omitted."},
            "no_safety_snapshot": NO_SAFETY_SNAPSHOT,
        },
        result=NO_RESULT, handler=_restore, cli="restore",
    ),
    _govern_job("project.recover", "Restart the build the health monitor stopped (recover).",
                _recover, "recover"),
    _govern_job("project.abandon_install",
                "Undo an open install before its hook ran (prod-deploy --abandon).",
                _abandon, "prod-deploy"),
)
