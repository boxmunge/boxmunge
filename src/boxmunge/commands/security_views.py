# SPDX-License-Identifier: Apache-2.0
"""Text and JSON formatters for `boxmunge security`.

Pure formatting — these helpers consume already-loaded manifest, scan state,
suppression, and quarantine data and emit strings. No I/O happens here so
the formatters are easy to unit-test.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from boxmunge.cve.policy import Disposition
from boxmunge.cve.scan_state import headline_from_scan_state
from boxmunge.security_overlay import (
    PROFILE_DEFAULT,
    POSTURE_BALANCED,
    resolve_security,
    services_with_off_profile,
)
from boxmunge.writable import describe_state, writable_json


# ---------- per-project view ----------


def _resolved_for_each_service(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    project_sec = manifest.get("security")
    out: dict[str, dict[str, Any]] = {}
    for svc_name, svc in (manifest.get("services") or {}).items():
        svc_sec = svc.get("security") if isinstance(svc, dict) else None
        out[svc_name] = resolve_security(project_sec, svc_sec)
    return out


def _format_iso_compact(iso: str | None) -> str:
    """Render an ISO timestamp as 'YYYY-MM-DD HH:MM UTC' for human prose."""
    if not iso:
        return "never"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return iso
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _project_status(
    *,
    quarantined: bool,
    quarantine_state: dict[str, Any] | None,
    scan_state: dict[str, Any] | None,
    dangerously_disable: bool,
) -> str:
    """Resolve the headline status string for the per-project view."""
    if quarantined:
        return "QUARANTINED"
    if scan_state is None:
        return "NORMAL"
    # If any decision is at-risk, surface AT_RISK_RUNNING.
    for decision in scan_state.get("decisions", []):
        for f in decision.get("findings", []):
            if f.get("disposition") == Disposition.STILL_RUNNING_AT_RISK.value:
                return "AT_RISK_RUNNING" if dangerously_disable else "NORMAL"
    return "NORMAL"


def _format_findings_block(scan_state: dict[str, Any]) -> list[str]:
    """Render each finding line under 'Findings (N):'."""
    findings: list[dict[str, Any]] = []
    for decision in scan_state.get("decisions", []):
        findings.extend(decision.get("findings") or [])

    lines: list[str] = []
    if not findings:
        lines.append("  Findings (0): clean")
        return lines

    lines.append(f"  Findings ({len(findings)}):")
    for f in findings:
        tag = f.get("disposition", "").upper()
        cve = f.get("cve_id", "")
        base = f.get("base_severity", "")
        eff = f.get("effective_severity", base)
        if base != eff:
            sev = f"{base} → effective {eff}"
        else:
            sev = base
        explanation = f.get("explanation", "") or ""
        # Take just the leading clause for the table-style line.
        short = explanation.split(".")[0].strip() or explanation.strip()
        lines.append(f"    [{tag:<14}] {cve:<14} {sev:<28} {short}")
    return lines


def format_project_text(
    manifest: dict[str, Any],
    *,
    posture: str,
    dangerously_disable_quarantine: bool,
    quarantined: bool,
    quarantine_state: dict[str, Any] | None,
    scan_state: dict[str, Any] | None,
    active_suppressions: tuple[Any, ...],
) -> str:
    """Render the per-project text view.

    Hardening section is emitted in the existing format; the CVE state
    section is appended.
    """
    project = manifest["project"]
    schema = manifest["schema_version"]
    project_sec = manifest.get("security") or {}
    project_profile = project_sec.get("profile", PROFILE_DEFAULT)

    lines = [f"project: {project} (schema_version: {schema}, profile: {project_profile})"]
    if project_sec.get("reason"):
        lines.append(f"  project reason: {project_sec['reason']!r}")
    lines.append("")

    resolved = _resolved_for_each_service(manifest)
    for svc_name, fragment in resolved.items():
        svc = manifest["services"][svc_name]
        svc_sec = svc.get("security") if isinstance(svc, dict) else None
        svc_profile = (svc_sec or {}).get("profile", project_profile)

        lines.append(f"  service: {svc_name}")
        lines.append(f"    profile:           {svc_profile}")
        if svc_sec and svc_sec.get("reason"):
            lines.append(f"    reason:            {svc_sec['reason']!r}")
        if not fragment:
            lines.append("    (no hardening applied — profile: off)")
            lines.append("")
            continue
        if "security_opt" in fragment:
            lines.append(f"    security_opt:      {fragment['security_opt']}")
        if "init" in fragment:
            lines.append(f"    init:              {fragment['init']}")
        if "pids_limit" in fragment:
            lines.append(f"    pids_limit:        {fragment['pids_limit']}")
        if "cap_drop" in fragment:
            lines.append(f"    cap_drop:          {fragment['cap_drop']}")
        if fragment.get("cap_add"):
            lines.append(f"    cap_add:           {fragment['cap_add']}")
        _, writable_desc = describe_state(svc)
        lines.append(f"    writable:          {writable_desc}")
        lines.append("")

    # CVE section ---------------------------------------------------------
    lines.append("CVE state:")
    lines.append(f"  posture:                          {posture}")
    lines.append(
        f"  dangerously_disable_quarantine:   "
        f"{'true' if dangerously_disable_quarantine else 'false'}"
    )

    status = _project_status(
        quarantined=quarantined,
        quarantine_state=quarantine_state,
        scan_state=scan_state,
        dangerously_disable=dangerously_disable_quarantine,
    )
    if quarantined and quarantine_state:
        when = _format_iso_compact(quarantine_state.get("quarantined_at"))
        lines.append(f"  status:                           {status} (since {when})")
        cve = quarantine_state.get("cve_id", "")
        sev = quarantine_state.get("severity", "")
        explanation = quarantine_state.get("explanation", "") or ""
        short = explanation.split(".")[0].strip() or explanation.strip()
        lines.append(f"  reason:                           {cve} {sev} ({short})")
    else:
        lines.append(f"  status:                           {status}")

    if scan_state is None:
        lines.append("  last scan:                        never")
        lines.append("")
        lines.append(
            f"  No CVE scans have run yet for this project. "
            f"Run `boxmunge security scan {project}` to scan now."
        )
    else:
        lines.append(
            f"  last scan:                        "
            f"{_format_iso_compact(scan_state.get('scanned_at'))}"
        )
        lines.append("")
        lines.extend(_format_findings_block(scan_state))

    if active_suppressions:
        lines.append("")
        lines.append("  Active suppressions:")
        for s in active_suppressions:
            lines.append(
                f"    {s.cve_id} (until {s.until.isoformat()}, "
                f"by {s.reviewed_by}: {s.reason!r})"
            )

    return "\n".join(lines)


def format_project_json(
    manifest: dict[str, Any],
    *,
    posture: str,
    dangerously_disable_quarantine: bool,
    quarantined: bool,
    quarantine_state: dict[str, Any] | None,
    scan_state: dict[str, Any] | None,
    active_suppressions: tuple[Any, ...],
) -> str:
    """Render the per-project JSON view.

    Extends the legacy hardening payload with a top-level `cve` key.
    """
    project = manifest["project"]
    project_sec = manifest.get("security") or {}
    payload: dict[str, Any] = {
        "project": project,
        "schema_version": manifest["schema_version"],
        "project_profile": project_sec.get("profile", PROFILE_DEFAULT),
        "project_reason": project_sec.get("reason"),
        "services": {},
        "off_services": [
            {"service": s, "reason": r}
            for s, r in services_with_off_profile(manifest)
        ],
    }
    for svc_name, fragment in _resolved_for_each_service(manifest).items():
        svc_block = manifest["services"][svc_name]
        # Extend the hardening fragment with v0.9 writable: state for
        # this service so JSON consumers see the surface choices.
        enriched = dict(fragment)
        enriched["writable"] = writable_json(svc_block)
        payload["services"][svc_name] = enriched

    findings_payload: list[dict[str, Any]] = []
    if scan_state is not None:
        for decision in scan_state.get("decisions", []):
            findings_payload.extend(decision.get("findings") or [])

    status = _project_status(
        quarantined=quarantined,
        quarantine_state=quarantine_state,
        scan_state=scan_state,
        dangerously_disable=dangerously_disable_quarantine,
    )

    payload["cve"] = {
        "posture": posture,
        "dangerously_disable_quarantine": dangerously_disable_quarantine,
        "status": status,
        "last_scan": (scan_state or {}).get("scanned_at"),
        "findings": findings_payload,
        "quarantine": quarantine_state if quarantined else None,
        "active_suppressions": [
            {
                "cve_id": s.cve_id,
                "until": s.until.isoformat(),
                "reason": s.reason,
                "reviewed_by": s.reviewed_by,
                "added": s.added.isoformat(),
            }
            for s in active_suppressions
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


# ---------- fleet summary ----------


def format_fleet_text(summary: dict[str, Any]) -> str:
    """Render the fleet-wide summary as text."""
    lines = ["boxmunge security — fleet summary"]
    lines.append("─" * 33)

    # Migration grace line (only when a marker file exists). We surface
    # active vs expired explicitly so the operator can see whether they're
    # still in the post-upgrade window.
    grace = summary.get("grace")
    if grace is not None:
        when = _format_iso_compact(grace.get("expires_at"))
        if grace.get("error"):
            lines.append(
                f"Migration grace: ERROR — {grace['error']}",
            )
        elif grace.get("active"):
            sent = "true" if grace.get("heads_up_sent") else "false"
            lines.append(
                f"Migration grace: ACTIVE — full enforcement begins {when} "
                f"(heads_up_sent: {sent})",
            )
        else:
            lines.append(f"Migration grace: expired (since {when})")

    lines.append(f"Projects: {summary['projects_count']}")
    lines.append("")
    lines.append("Posture distribution:")
    for posture in ("balanced", "strict", "relaxed"):
        n = summary["posture_distribution"].get(posture, 0)
        lines.append(f"  {posture}: {n}")
    lines.append("")
    quarantined = summary.get("quarantined") or []
    lines.append(f"Quarantined: {len(quarantined)}")
    for q in quarantined:
        when = _format_iso_compact(q.get("since"))
        lines.append(
            f"  - {q['project']} — {q['cve_id']} {q['severity']} (since {when})"
        )
    lines.append("")
    at_risk = summary.get("at_risk_running") or []
    lines.append(
        f"At-risk running (dangerously_disable_quarantine): {len(at_risk)}"
    )
    for name in at_risk:
        lines.append(f"  - {name}")
    lines.append("")
    proj_count = summary.get("active_suppressions_projects", 0)
    n_supps = summary.get("active_suppressions_count", 0)
    lines.append(
        f"Active suppressions: {n_supps} (across {proj_count} projects)"
    )
    lines.append("")
    last = summary.get("last_fleet_scan")
    lines.append(f"Last fleet scan: {_format_iso_compact(last)}")
    return "\n".join(lines)


def format_fleet_json(summary: dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, sort_keys=True)
