# SPDX-License-Identifier: Apache-2.0
"""Operate actions over a project's releases, each a job over the core its
CLI command runs: project.stage, project.promote, project.unstage,
project.deploy and project.rollback.

A dry run stays CLI-only: it prints a plan, which a job has no one to show.
A rollback works out its target under the lock, as `rollback --yes` does.
"""
from __future__ import annotations

from typing import Any

from boxmunge.api.actions._operate import (
    ALLOW_REGRESSION, NO_PULL, REF, operate_job, regression_allowed, run_core,
)
from boxmunge.api.context import ActionContext
from boxmunge.api.schema import BOOLEAN, STRING, obj
from boxmunge.commands.deploy import deploy_locked
from boxmunge.commands.kev_acceptance import prod_deploy_acceptance
from boxmunge.commands.promote_cmd import promote_locked
from boxmunge.commands.rollback import rollback_locked
from boxmunge.commands.stage_cmd import stage_locked
from boxmunge.commands.unstage_cmd import unstage_locked
from boxmunge.staged_release import load_slot

NO_RESULT = obj({})
RELEASE_REF = {**REF, "description": "The bundle timestamp or git ref to release (--ref)."}
ACCEPT_STALE_KEV = {
    **BOOLEAN, "x-tier": "govern",
    "description": "Deploy although there is no usable CISA KEV catalog; logged and "
                   "alerted (--accept-stale-kev).",
}


def _stage(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    project = params["project"]
    with regression_allowed(ctx.paths, params):
        run_core("stage", lambda: stage_locked(
            project, ctx.paths, ref=params.get("ref"), dry_run=False,
            pull=not params.get("no_pull", False)))
    slot = load_slot(ctx.paths, project)
    if slot is None:
        raise RuntimeError(f"stage of {project} exited 0 but left no staged release")
    return {"ref": slot.ref, "id": slot.id}


def _promote(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    with regression_allowed(ctx.paths, params):
        run_core("promote", lambda: promote_locked(
            params["project"], ctx.paths, dry_run=False,
            pull=not params.get("no_pull", False)))
    return {}


def _unstage(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    run_core("unstage", lambda: unstage_locked(params["project"], ctx.paths, dry_run=False))
    return {}


def _deploy(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    project = params["project"]
    with (prod_deploy_acceptance(ctx.paths, project, params.get("accept_stale_kev", False)),
          regression_allowed(ctx.paths, params)):
        run_core("prod-deploy", lambda: deploy_locked(
            project, ctx.paths, ref=params.get("ref"),
            no_snapshot=params.get("no_snapshot", False), dry_run=False,
            pull=not params.get("no_pull", False), redeploy=params.get("redeploy", False)))
    return {}


def _rollback(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    with regression_allowed(ctx.paths, params):
        run_core("rollback", lambda: rollback_locked(params["project"], ctx.paths))
    return {}


ACTIONS = (
    operate_job(
        "project.stage", "Stage a release beside production for testing (stage).",
        params={"ref": RELEASE_REF, "no_pull": NO_PULL,
                "allow_security_regression": ALLOW_REGRESSION},
        result=obj({"ref": STRING, "id": STRING}), handler=_stage, cli="stage",
    ),
    operate_job(
        "project.promote", "Promote the staged release to production (promote).",
        params={"no_pull": NO_PULL, "allow_security_regression": ALLOW_REGRESSION},
        result=NO_RESULT, handler=_promote, cli="promote",
    ),
    operate_job(
        "project.unstage", "Tear down the staged release; production is untouched (unstage).",
        params={}, result=NO_RESULT, handler=_unstage, cli="unstage",
    ),
    operate_job(
        "project.deploy", "Deploy a release to production (prod-deploy).",
        params={
            "ref": RELEASE_REF,
            "no_snapshot": {**BOOLEAN, "description": "Skip the pre-deploy snapshot "
                                                       "(--no-snapshot)."},
            "no_pull": NO_PULL,
            "redeploy": {**BOOLEAN, "description": "Deploy the installed release again "
                                                    "(--redeploy)."},
            "accept_stale_kev": ACCEPT_STALE_KEV,
            "allow_security_regression": ALLOW_REGRESSION,
        },
        result=NO_RESULT, handler=_deploy, cli="prod-deploy",
    ),
    operate_job(
        "project.rollback", "Return production to the previous release and its data "
                            "(rollback).",
        params={"allow_security_regression": ALLOW_REGRESSION},
        result=NO_RESULT, handler=_rollback, cli="rollback",
    ),
)
