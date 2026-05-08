# SPDX-License-Identifier: Apache-2.0
"""Alert-body formatters for CVE policy state transitions.

Extracted from ``cve/alerting.py`` to keep that module under the 500-line
budget. Pure functions: take in-memory values, return ``Alert`` instances.
No I/O, no logging.

The public ``Alert`` / ``AlertKind`` symbols and the dispatch logic
(``detect_transitions``, ``send_alerts``, ``emit_scan_alerts``) live in
``alerting.py``; consumers should keep importing from there.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

from boxmunge.cve._alerting_types import Alert
from boxmunge.cve.policy import (
    Disposition,
    FindingDisposition,
    ProjectDecision,
)
from boxmunge.cve.suppressions import Suppression


# ---------- per-disposition formatters ----------


def format_quarantine_alert(
    decision: ProjectDecision, finding: FindingDisposition,
) -> Alert:
    """Format a "newly quarantined" alert. Priority 1."""
    project = decision.project_name
    cve = finding.finding.cve_id
    severity = finding.effective_severity.value
    image_ref = decision.image_ref
    title = f"[boxmunge:{project}] QUARANTINED — {cve} ({severity})"
    body = (
        f"Project: {project}\n"
        f"CVE: {cve} ({severity}, no upstream fix)\n"
        f"Image: {image_ref}\n"
        f"\n"
        f"Service stopped, maintenance page active.\n"
        f"\n"
        f"To resume: boxmunge security resume {project}\n"
        f"(after the CVE is fixed upstream or you add a suppression)"
    )
    return Alert(kind="quarantine", title=title, body=body, priority=1)


def format_still_running_alert(
    decision: ProjectDecision, finding: FindingDisposition,
) -> Alert:
    """Format a "still running at risk" alert. Priority 1.

    Fires when a finding would quarantine but the project's manifest has
    `dangerously_disable_quarantine: true`.
    """
    project = decision.project_name
    cve = finding.finding.cve_id
    severity = finding.effective_severity.value
    image_ref = decision.image_ref
    title = f"[boxmunge:{project}] [STILL RUNNING] {cve} ({severity})"
    body = (
        f"Project: {project} — QUARANTINE DISABLED BY CONFIG\n"
        f"CVE: {cve} ({severity}, no upstream fix)\n"
        f"Image: {image_ref}\n"
        f"\n"
        f"Project is still running because dangerously_disable_quarantine is true.\n"
        f"Read-only rootfs is the only remaining post-exploit defense.\n"
        f"\n"
        f"To remove the exemption: drop dangerously_disable_quarantine from the\n"
        f"manifest's security: block. To suppress this specific CVE:\n"
        f"  boxmunge security suppress {cve} --project {project} \\\n"
        f"      --until <date> --reason <text>"
    )
    return Alert(kind="still_running", title=title, body=body, priority=1)


def format_informational_alert(
    decision: ProjectDecision, finding: FindingDisposition, posture: str,
) -> Alert:
    """Format a sub-threshold informational alert. Priority 0."""
    project = decision.project_name
    cve = finding.finding.cve_id
    image_ref = decision.image_ref
    base = finding.base_severity.value
    effective = finding.effective_severity.value
    title = f"[boxmunge:{project}] {cve} ({effective})"
    if finding.hardening_penalty > 0 and base != effective:
        sev_line = (
            f"Severity: {base} → effective {effective} via penalty "
            f"+{finding.hardening_penalty}"
        )
    else:
        sev_line = f"Severity: {base}"
    body = (
        f"Project: {project}\n"
        f"CVE: {cve}\n"
        f"{sev_line}\n"
        f"Image: {image_ref}\n"
        f"\n"
        f"Below quarantine threshold ({posture} posture). Monitoring only."
    )
    return Alert(kind="informational", title=title, body=body, priority=0)


def format_suppression_expired_alert(
    project_name: str, suppression: Suppression,
) -> Alert:
    """Format a "suppression expired between scans" alert. Priority 1."""
    title = (
        f"[boxmunge:{project_name}] Suppression expired — {suppression.cve_id}"
    )
    body = (
        f"Project: {project_name}\n"
        f"CVE: {suppression.cve_id}\n"
        f"Suppression added: {suppression.added.isoformat()}\n"
        f"Suppression expired: {suppression.until.isoformat()}\n"
        f"\n"
        f"This is now an active finding. Quarantine queued for next scan.\n"
        f"To extend the suppression:\n"
        f"  boxmunge security suppress {suppression.cve_id} "
        f"--project {project_name} \\\n"
        f"      --until <date> --reason <text>"
    )
    return Alert(
        kind="suppression_expired", title=title, body=body, priority=1,
    )


# ---------- grace heads-up helpers ----------


def _quarantine_findings(
    decision: ProjectDecision,
) -> tuple[FindingDisposition, ...]:
    return tuple(
        d for d in decision.findings if d.disposition == Disposition.QUARANTINE
    )


def _at_risk_findings(
    decision: ProjectDecision,
) -> tuple[FindingDisposition, ...]:
    return tuple(
        d for d in decision.findings
        if d.disposition == Disposition.STILL_RUNNING_AT_RISK
    )


def _format_finding_summary(fd: FindingDisposition) -> str:
    """Compact 'CVE-... (Severity, ...)' clause used in heads-up bullets.

    Mirrors the explanation prefix used elsewhere so the operator sees
    consistent severity wording across alert kinds.
    """
    cve = fd.finding.cve_id
    base = fd.base_severity.value
    eff = fd.effective_severity.value
    if base != eff and fd.hardening_penalty > 0:
        return (
            f"{cve} ({base} → effective {eff} via hardening penalty, "
            f"no upstream fix)"
        )
    return f"{cve} ({eff}, no upstream fix)"


def format_grace_heads_up_alert(
    *,
    expires_at: datetime,
    decisions_by_project: dict[str, ProjectDecision],
    posture_by_project: dict[str, str],
    dangerously_by_project: dict[str, bool],
) -> Alert:
    """One-time fleet-level "heads-up" alert for the migration grace window.

    Lists projects that *would* quarantine at grace expiry and projects
    running with ``dangerously_disable_quarantine`` that hit a finding
    over their posture threshold. Includes posture pointers and the
    suppression command syntax so the operator can configure before
    enforcement bites.

    Empty sections are omitted entirely (no "none." line).
    """
    # Compute "hours remaining" relative to "now" — clamped >=1 so the
    # title always reads sensibly even if the window is on the edge.
    now = datetime.now(timezone.utc)
    delta = expires_at - now
    hours_remaining = max(1, math.ceil(delta.total_seconds() / 3600))
    title = (
        f"[boxmunge] CVE policy enforcement begins in {hours_remaining}h"
    )

    # Bucket projects.
    #
    # Audit F-7: the at-risk-running section is populated by intersecting
    # `dangerously_by_project` (the operator-declared exemption) with the
    # set of projects that have would-quarantine findings. A project with
    # the dangerously flag set but no findings over its posture threshold
    # is NOT at-risk-running and must not be listed; conversely, a project
    # without the flag whose findings are STILL_RUNNING_AT_RISK has no
    # way to land that disposition without the flag — so the two
    # signals are equivalent in practice today, but we read the explicit
    # dict so the alert body matches the source-of-truth signal the
    # caller supplies (rather than a derived view of it).
    would_quarantine: list[tuple[str, FindingDisposition]] = []
    at_risk: list[tuple[str, FindingDisposition]] = []
    other_projects: list[str] = []
    for name in sorted(decisions_by_project.keys()):
        decision = decisions_by_project[name]
        q_findings = _quarantine_findings(decision)
        r_findings = _at_risk_findings(decision)
        if q_findings:
            # One representative finding per project — most-severe first
            # is already the convention from policy.evaluate_project.
            would_quarantine.append((name, q_findings[0]))
        elif r_findings and dangerously_by_project.get(name) is True:
            at_risk.append((name, r_findings[0]))
        else:
            other_projects.append(name)

    n_projects = len(decisions_by_project)
    n_quar = len(would_quarantine)
    n_risk = len(at_risk)
    n_other = len(other_projects)

    expires_display = expires_at.astimezone(timezone.utc).strftime(
        "%Y-%m-%d %H:%M",
    )

    lines: list[str] = []
    lines.append(
        "boxmunge v0.6.0 introduces CVE policy. After a 24-hour grace "
        "window, projects",
    )
    lines.append(
        "with unpatched high-severity CVEs will be quarantined "
        "automatically.",
    )
    lines.append("")
    lines.append(f"First scan results across {n_projects} projects:")
    lines.append("")

    # Would-quarantine section.
    if would_quarantine:
        lines.append(
            f"Would quarantine after grace ends ({n_quar} projects):",
        )
        # Align project names for readability — width ~12 unless longer.
        name_width = max(len(name) for name, _ in would_quarantine)
        for name, fd in would_quarantine:
            posture = posture_by_project.get(name, "balanced")
            summary = _format_finding_summary(fd)
            lines.append(
                f"  - {name:<{name_width}}  {summary} — posture: {posture}",
            )
    else:
        lines.append(
            "Would quarantine after grace ends: No projects would be "
            "quarantined.",
        )
    lines.append("")

    # At-risk-running section. Audit F-7: omit entirely when empty
    # (matches the "don't show empty bullet lists" pattern; the prior
    # "none." line was an exception that the audit flagged for cleanup).
    if at_risk:
        lines.append(
            f"At-risk-running (dangerously_disable_quarantine={n_risk} "
            f"projects):",
        )
        name_width = max(len(name) for name, _ in at_risk)
        for name, fd in at_risk:
            summary = _format_finding_summary(fd)
            lines.append(f"  - {name:<{name_width}}  {summary}")
        lines.append("")

    lines.append(f"Other projects ({n_other}): clean or sub-threshold findings only.")
    lines.append("")
    lines.append("Configure per-project posture in manifest.yml:")
    lines.append("  security:")
    lines.append("    posture: relaxed | balanced (default) | strict")
    lines.append("")
    lines.append("Suppress a specific CVE (with operator review):")
    lines.append(
        "  boxmunge security suppress <CVE> --project <name> \\",
    )
    lines.append("      --until <date> --reason <text>")
    lines.append("")
    lines.append(f"Enforcement begins: {expires_display} UTC")

    body = "\n".join(lines)
    return Alert(
        kind="grace_heads_up", title=title, body=body, priority=1,
    )
