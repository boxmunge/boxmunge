# SPDX-License-Identifier: Apache-2.0
"""Observe actions over jobs: jobs.list, job.get, job.events."""
from __future__ import annotations

from typing import Any

from boxmunge.api.actions._common import PROJECT_PARAM
from boxmunge.api.context import ActionContext
from boxmunge.api.jobs import EVENT_SCHEMA, JOB_ID_PATTERN, JOB_SCHEMA, JobStore
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Action
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import STRING, arr, obj

JOBS_LIMIT_DEFAULT = 50
JOB_ID_PARAM: dict[str, Any] = {"type": "string", "pattern": JOB_ID_PATTERN,
                                "description": "Job id (a ULID)."}


def _jobs_list(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    listing = _store(ctx).recent(project=params.get("project"),
                                 limit=params.get("limit", JOBS_LIMIT_DEFAULT))
    result: dict[str, Any] = {"jobs": listing.jobs}
    if listing.unreadable:
        result["unreadable"] = listing.unreadable
    return result


def _store(ctx: ActionContext) -> JobStore:
    return JobStore(ctx.paths, result_schemas=ctx.result_schemas)


def _job_get(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    return _require_job(_store(ctx), params["id"])


def _job_events(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    store = _store(ctx)
    job_id = params["id"]
    _require_job(store, job_id)
    return {"id": job_id, "events": store.events(job_id, after=params.get("after", 0))}


def _require_job(store: JobStore, job_id: str) -> dict[str, Any]:
    record = store.get(job_id)
    if record is None:
        raise ActionError(ErrorCode.NOT_FOUND,
                          f"No job {job_id}. jobs.list shows recent jobs.")
    return record


ACTIONS = (
    Action(
        name="jobs.list", tier=Tier.OBSERVE,
        summary="Recent jobs, newest first, optionally for one project.",
        params=obj({
            "project": PROJECT_PARAM,
            "limit": {"type": "integer", "minimum": 1, "maximum": 200,
                      "description": f"At most this many jobs. Default {JOBS_LIMIT_DEFAULT}."},
        }, optional=("project", "limit")),
        result=obj({
            "jobs": arr(JOB_SCHEMA),
            "unreadable": {**arr(obj({"id": STRING, "problem": STRING})),
                           "description": "Job records that could not be read, each "
                                          "with the problem; present only when any are."},
        }, optional=("unreadable",)), handler=_jobs_list, mcp=True,
    ),
    Action(
        name="job.get", tier=Tier.OBSERVE,
        summary="One job's record: action, principal, state, times and error.",
        params=obj({"id": JOB_ID_PARAM}), result=JOB_SCHEMA, handler=_job_get, mcp=True,
    ),
    Action(
        name="job.events", tier=Tier.OBSERVE,
        summary="A job's events in order; pass after to fetch only newer ones.",
        params=obj({
            "id": JOB_ID_PARAM,
            "after": {"type": "integer", "minimum": 0,
                      "description": "Only events with a greater seq. Default 0."},
        }, optional=("after",)),
        result=obj({"id": STRING, "events": arr(EVENT_SCHEMA)}),
        handler=_job_events, mcp=True,
    ),
)
