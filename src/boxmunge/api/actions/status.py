# SPDX-License-Identifier: Apache-2.0
"""Observe actions about the whole box: platform.info, status.get,
projects.list, health.get."""
from __future__ import annotations

from typing import Any

from boxmunge.api import API_VERSION
from boxmunge.api.actions._common import NO_PARAMS
from boxmunge.api.context import ActionContext
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Action
from boxmunge.api.schema import BOOLEAN, INTEGER, STRING, arr, enum, obj
from boxmunge.commands.handshake_cmd import run_handshake
from boxmunge.commands.status import collect_status
from boxmunge.config import load_config
from boxmunge.project_registry import load_registered_projects
from boxmunge.version import get_build_version

PLATFORM_INFO = obj({
    "api_version": STRING,
    "server_version": STRING,
    "build": STRING,
    "min_client_version": STRING,
    "schema_version": INTEGER,
    "hostname": STRING,
})

STATUS_ROW = obj({
    "project": STRING, "status": STRING, "raw_status": STRING,
    "last_check": STRING, "deployed_at": STRING,
    "cve_id": STRING, "severity": STRING, "explanation": STRING,
    "quarantined_at": STRING, "error": STRING,
}, optional=("cve_id", "severity", "explanation", "quarantined_at", "error"))

HEALTH_REPORT = obj({
    "healthy": BOOLEAN,
    "exit_code": INTEGER,
    "checks": arr(obj({
        "name": STRING,
        "status": enum("ok", "warn", "error", "skip"),
        "detail": STRING,
    })),
})


def _platform_info(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    handshake = run_handshake()
    return {
        "api_version": API_VERSION,
        "server_version": handshake["server_version"],
        "build": get_build_version(),
        "min_client_version": handshake["min_client_version"],
        "schema_version": handshake["schema_version"],
        "hostname": load_config(ctx.paths)["hostname"],
    }


def _status_get(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    return {"projects": collect_status(ctx.paths).rows}


def _projects_list(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    return {"projects": sorted(load_registered_projects(ctx.paths))}


def _health_get(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    return ctx.host.health_report()


ACTIONS = (
    Action(
        name="platform.info", tier=Tier.OBSERVE,
        summary="Versions, hostname and API version of this box.",
        params=NO_PARAMS, result=PLATFORM_INFO, handler=_platform_info,
        cli="handshake", mcp=True,
    ),
    Action(
        name="status.get", tier=Tier.OBSERVE,
        summary="One dashboard row per project: lifecycle, health and last deploy.",
        params=NO_PARAMS, result=obj({"projects": arr(STATUS_ROW)}), handler=_status_get,
        cli="status", mcp=True,
    ),
    Action(
        name="projects.list", tier=Tier.OBSERVE,
        summary="Names of the projects registered on this box.",
        params=NO_PARAMS, result=obj({"projects": arr(STRING)}), handler=_projects_list,
        cli="project-list", mcp=True,
    ),
    Action(
        name="health.get", tier=Tier.OBSERVE,
        summary="Platform health checks: Docker, Caddy, backup key, host hardening.",
        params=NO_PARAMS, result=HEALTH_REPORT, handler=_health_get,
        cli="health", mcp=True,
    ),
)
