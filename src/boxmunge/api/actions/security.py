# SPDX-License-Identifier: Apache-2.0
"""Observe actions over CVE policy: security.summary (the fleet) and
security.project (one project's findings and dispositions)."""
from __future__ import annotations

from typing import Any

from boxmunge.api.actions._common import (
    NO_PARAMS, PROJECT_PARAM, QUARANTINE_SCHEMA, deployed_project, quarantine_view,
)
from boxmunge.api.context import ActionContext
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Action
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import (
    BOOLEAN, INTEGER, NULLABLE_BOOLEAN, NULLABLE_INTEGER, NULLABLE_STRING, STRING,
    arr, enum, nullable, obj,
)
from boxmunge.commands.security_cmd import (
    SecurityViewError, fleet_summary, load_project_security,
)
from boxmunge.commands.security_views import project_cve_status
from boxmunge.cve.breaker import BreakerError, read_held
from boxmunge.cve.policy import Disposition
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import services_with_off_profile

POSTURES = ("relaxed", "balanced", "strict", "paranoid")

SUMMARY = obj({
    "projects_count": INTEGER,
    "posture_distribution": obj({posture: INTEGER for posture in POSTURES}),
    "quarantined": arr(obj({
        "project": STRING, "cve_id": STRING, "severity": STRING, "since": NULLABLE_STRING,
    })),
    "at_risk_running": arr(STRING),
    "active_suppressions_count": INTEGER,
    "active_suppressions_projects": INTEGER,
    "active_suppressions_host": INTEGER,
    "host_suppressions": arr(obj({"cve_id": STRING, "until": STRING, "reason": STRING})),
    "last_fleet_scan": NULLABLE_STRING,
    "grace": nullable(obj({
        "active": BOOLEAN, "installed_at": NULLABLE_STRING, "expires_at": NULLABLE_STRING,
        "heads_up_sent": BOOLEAN, "error": STRING,
    }, optional=("error",))),
    "held_by_breaker": obj({
        "projects": arr(obj({"project": STRING, "cves": arr(STRING)})),
        "error": NULLABLE_STRING,
    }),
    # Projects left out of the counts because a file could not be read; a
    # null project is the box-wide host suppressions file.
    "unreadable": arr(obj({"project": NULLABLE_STRING, "error": STRING})),
})

# Keys older scan-state files may lack; they read back as null.
_OPTIONAL_FINDING_KEYS: dict[str, dict[str, Any]] = {
    "explanation": NULLABLE_STRING, "package": NULLABLE_STRING, "title": NULLABLE_STRING,
    "installed_version": NULLABLE_STRING, "fixed_version": NULLABLE_STRING,
    "primary_url": NULLABLE_STRING, "attack_vector": NULLABLE_STRING,
    "status": NULLABLE_STRING, "pkg_class": NULLABLE_STRING, "pkg_type": NULLABLE_STRING,
    "fix_available": NULLABLE_BOOLEAN, "kev_listed": NULLABLE_BOOLEAN,
    "fix_would_quarantine": NULLABLE_BOOLEAN, "hardening_penalty": NULLABLE_INTEGER,
}

FINDING = obj({
    "image_ref": NULLABLE_STRING,
    "cve_id": STRING,
    "disposition": enum(*(d.value for d in Disposition)),
    "base_severity": STRING,
    "effective_severity": STRING,
    **_OPTIONAL_FINDING_KEYS,
})

PROJECT_SECURITY = obj({
    "project": STRING,
    "posture": STRING,
    "dangerously_disable_quarantine": BOOLEAN,
    "status": enum("NORMAL", "QUARANTINED", "AT_RISK_RUNNING"),
    "last_scan": NULLABLE_STRING,
    "unscanned": arr(STRING),
    "findings": arr(FINDING),
    "quarantine": nullable(QUARANTINE_SCHEMA),
    "active_suppressions": arr(obj({
        "cve_id": STRING, "until": STRING, "reason": STRING, "reviewed_by": STRING,
        "added": STRING, "scope": enum("project", "host"),
    })),
    "off_services": arr(obj({"service": STRING, "reason": STRING})),
})


def _security_summary(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    summary = fleet_summary(ctx.paths)
    summary["held_by_breaker"] = _held(ctx.paths)
    return summary


def _held(paths: BoxPaths) -> dict[str, Any]:
    """Breaker-held quarantines as a list, so a project named "error" cannot
    collide with the error field."""
    try:
        held = read_held(paths)
    except BreakerError as e:
        return {"projects": [], "error": str(e)}
    return {
        "projects": [{"project": name, "cves": sorted(cves)}
                     for name, cves in sorted(held.items())],
        "error": None,
    }


def _security_project(params: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
    name = params["project"]
    deployed_project(ctx.paths, name)
    try:
        view = load_project_security(name, ctx.paths)
    except SecurityViewError as e:
        raise ActionError(ErrorCode.FAILED, str(e)) from e
    scan = view.scan_state or {}
    return {
        "project": name,
        "posture": view.posture,
        "dangerously_disable_quarantine": view.dangerously_disable_quarantine,
        "status": project_cve_status(
            quarantined=view.quarantined, quarantine_state=view.quarantine_state,
            scan_state=view.scan_state,
            dangerously_disable=view.dangerously_disable_quarantine),
        "last_scan": scan.get("scanned_at"),
        "unscanned": list(scan.get("unscanned", [])),
        "findings": [
            _finding_view(finding, decision.get("image_ref"))
            for decision in scan.get("decisions", [])
            for finding in decision.get("findings") or []
        ],
        "quarantine": quarantine_view(view.quarantine_state) if view.quarantined else None,
        "active_suppressions": [
            {"cve_id": s.cve_id, "until": s.until.isoformat(), "reason": s.reason,
             "reviewed_by": s.reviewed_by, "added": s.added.isoformat(), "scope": s.scope}
            for s in view.active_suppressions
        ],
        "off_services": [{"service": service, "reason": reason}
                         for service, reason in services_with_off_profile(view.manifest)],
    }


def _finding_view(finding: dict[str, Any], image_ref: str | None) -> dict[str, Any]:
    return {
        "image_ref": image_ref,
        "cve_id": finding["cve_id"],
        "disposition": finding["disposition"],
        "base_severity": finding["base_severity"],
        "effective_severity": finding["effective_severity"],
        **{key: finding.get(key) for key in _OPTIONAL_FINDING_KEYS},
    }


ACTIONS = (
    Action(
        name="security.summary", tier=Tier.OBSERVE,
        summary="Fleet CVE view: postures, quarantines, at-risk projects, suppressions.",
        params=NO_PARAMS, result=SUMMARY, handler=_security_summary,
        cli="security", mcp=True,
    ),
    Action(
        name="security.project", tier=Tier.OBSERVE,
        summary="One project's CVE findings, dispositions, quarantine and suppressions.",
        params=obj({"project": PROJECT_PARAM}), result=PROJECT_SECURITY,
        handler=_security_project, cli="security", mcp=True,
    ),
)
