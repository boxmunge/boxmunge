# SPDX-License-Identifier: Apache-2.0
"""Observe actions over CVE policy: security.summary (the fleet) and
security.project (one project's findings and dispositions)."""
from __future__ import annotations

from typing import Any

from boxmunge.api.actions._common import (
    NO_PARAMS, PROJECT_PARAM, QUARANTINE_SCHEMA, SEVERITY, deployed_project, machine_enum,
    machine_value, quarantine_view, severity_value,
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
from boxmunge.api.timefmt import NULLABLE_TIMESTAMP, utc_timestamp
from boxmunge.cve.breaker import BreakerError, read_held
from boxmunge.cve.policy import Disposition
from boxmunge.cve.scan_state import (
    attack_vector_from_stored, pkg_class_from_stored, status_from_stored, stored_severities,
)
from boxmunge.cve.scanner import AttackVector, PkgClass, VulnStatus
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import services_with_off_profile

POSTURES = ("relaxed", "balanced", "strict", "paranoid")

SUMMARY = obj({
    "projects_count": INTEGER,
    "posture_distribution": obj({posture: INTEGER for posture in POSTURES}),
    "quarantined": arr(obj({
        "project": STRING, "cve_id": STRING, "severity": SEVERITY, "since": NULLABLE_TIMESTAMP,
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
    # null project is a box-wide file (host suppressions, the project
    # registry), which the error names.
    "unreadable": arr(obj({"project": NULLABLE_STRING, "error": STRING})),
})

# Keys older scan-state files may lack; they read back as null.
_OPTIONAL_FINDING_KEYS: dict[str, dict[str, Any]] = {
    "explanation": NULLABLE_STRING, "package": NULLABLE_STRING, "title": NULLABLE_STRING,
    "installed_version": NULLABLE_STRING, "fixed_version": NULLABLE_STRING,
    "primary_url": NULLABLE_STRING, "attack_vector": nullable(machine_enum(AttackVector)),
    "status": nullable(machine_enum(VulnStatus)), "pkg_class": nullable(machine_enum(PkgClass)),
    "pkg_type": NULLABLE_STRING,
    "fix_available": NULLABLE_BOOLEAN, "kev_listed": NULLABLE_BOOLEAN,
    "fix_would_quarantine": NULLABLE_BOOLEAN, "hardening_penalty": NULLABLE_INTEGER,
}

FINDING = obj({
    "image_ref": NULLABLE_STRING,
    "cve_id": STRING,
    "disposition": enum(*(d.value for d in Disposition)),
    "base_severity": SEVERITY,
    "effective_severity": SEVERITY,
    **_OPTIONAL_FINDING_KEYS,
})

PROJECT_SECURITY = obj({
    "project": STRING,
    "posture": STRING,
    "dangerously_disable_quarantine": BOOLEAN,
    "status": enum("normal", "quarantined", "at_risk_running"),
    "last_scan": NULLABLE_TIMESTAMP,
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
    summary.setdefault("unreadable", [])  # the CLI omits it when empty; the API always has it
    summary["held_by_breaker"] = _held(ctx.paths)
    for entry in summary["quarantined"]:
        entry["severity"] = severity_value(entry["severity"])
        entry["since"] = utc_timestamp(
            entry["since"], f"{ctx.paths.project_quarantine_state(entry['project'])} "
                            f"quarantined_at")
    summary["last_fleet_scan"] = utc_timestamp(summary["last_fleet_scan"], "the latest scan state")
    grace = summary["grace"]
    if grace is not None:
        for key in ("installed_at", "expires_at"):
            grace[key] = utc_timestamp(grace[key], f"the migration grace state {key}")
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
            dangerously_disable=view.dangerously_disable_quarantine).lower(),
        "last_scan": utc_timestamp(scan.get("scanned_at"),
                                   f"{ctx.paths.project_scan_state(name)} scanned_at"),
        "unscanned": list(scan.get("unscanned", [])),
        "findings": [
            _finding_view(finding, decision.get("image_ref"))
            for decision in scan.get("decisions", [])
            for finding in decision.get("findings") or []
        ],
        "quarantine": quarantine_view(
            view.quarantine_state, ctx.paths.project_quarantine_state(name),
        ) if view.quarantined else None,
        "active_suppressions": [
            {"cve_id": s.cve_id, "until": s.until.isoformat(), "reason": s.reason,
             "reviewed_by": s.reviewed_by, "added": s.added.isoformat(), "scope": s.scope}
            for s in view.active_suppressions
        ],
        "off_services": [{"service": service, "reason": reason}
                         for service, reason in services_with_off_profile(view.manifest)],
    }


def _finding_view(finding: dict[str, Any], image_ref: str | None) -> dict[str, Any]:
    base, effective = stored_severities(finding)
    return {
        "image_ref": image_ref,
        "cve_id": finding["cve_id"],
        "disposition": finding["disposition"],
        "base_severity": machine_value(base),
        "effective_severity": machine_value(effective),
        **{key: finding.get(key) for key in _OPTIONAL_FINDING_KEYS},
        **{key: _machine(finding, key, read) for key, read in _ENUM_FINDING_KEYS.items()},
    }


# Optional finding keys holding a stored enum, read as the platform reads them.
_ENUM_FINDING_KEYS = {
    "attack_vector": attack_vector_from_stored,
    "status": status_from_stored,
    "pkg_class": pkg_class_from_stored,
}


def _machine(finding: dict[str, Any], key: str, read: Any) -> str | None:
    """A key older scan files lack stays null; otherwise its machine value."""
    if finding.get(key) is None:
        return None
    member = read(finding[key])
    return None if member is None else machine_value(member)


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
