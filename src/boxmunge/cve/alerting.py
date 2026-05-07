# SPDX-License-Identifier: Apache-2.0
"""Pushover alerting for CVE policy state transitions.

This module turns a pair of (prior, current) ProjectDecisions plus the
current suppression list into a tuple of Alerts and pushes them through
the existing pushover.send_notification path.

Design properties
-----------------
* Pure transition detection — formatters and detect_transitions take only
  in-memory values and emit no I/O. Tests exercise them without mocking.
* Best-effort delivery — the durable record is the on-disk scan_state JSON;
  Pushover failures or missing config DO NOT fail the scan. Failures are
  logged at WARNING. (This is the one documented exception to the project
  "fail noisily, no fallbacks" rule: alert delivery is explicitly best
  effort because the scan must persist regardless.)
* No spam — alerts fire only on a state CHANGE between prior and current
  scans. A finding that stayed at the same disposition since the prior
  scan produces zero alerts. Recovery alerts (good news) are NOT emitted
  here; the operator sees them on their next look at `boxmunge security`.

Follow-ups
----------
* Priority 2 (Pushover emergency-ack with retry/expire) is intentionally
  out of scope for v0.6.0. It would require extending pushover.py with the
  retry/expire parameters; until then, the four critical-tier categories
  use priority 1 (high-priority — bypasses the user's quiet hours).
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from boxmunge.config import ConfigError, load_config
from boxmunge.cve.policy import (
    Disposition,
    FindingDisposition,
    ProjectDecision,
)
from boxmunge.cve.suppressions import Suppression
from boxmunge.paths import BoxPaths
from boxmunge.pushover import send_notification


_LOGGER = logging.getLogger("boxmunge")


def _extra(
    project: str | None = None, detail: dict | None = None,
) -> dict:
    """Structured-extras helper for cve-alert events."""
    return {"component": "cve-alert", "project": project, "detail": detail}


AlertKind = Literal[
    "quarantine",
    "still_running",
    "informational",
    "suppression_expired",
    "grace_heads_up",
]


@dataclass(frozen=True)
class Alert:
    """A single notification to send. Pure data — no I/O."""

    kind: AlertKind
    title: str
    body: str
    priority: int  # 0 = normal, 1 = high (bypasses quiet hours)


# ---------- formatters ----------


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

    Empty sections are rendered as "No projects ..." prose; no empty
    bullet lists.
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
        elif r_findings:
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

    # At-risk-running section.
    if at_risk:
        lines.append(
            f"At-risk-running (dangerously_disable_quarantine={n_risk} "
            f"projects):",
        )
        name_width = max(len(name) for name, _ in at_risk)
        for name, fd in at_risk:
            summary = _format_finding_summary(fd)
            lines.append(f"  - {name:<{name_width}}  {summary}")
    else:
        lines.append(
            "At-risk-running (dangerously_disable_quarantine): none.",
        )
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


# ---------- transition detection ----------


def _dispositions_by_cve(
    decision: ProjectDecision | None,
) -> dict[str, FindingDisposition]:
    """Map cve_id → FindingDisposition. Empty dict for None."""
    if decision is None:
        return {}
    return {fd.finding.cve_id: fd for fd in decision.findings}


def detect_transitions(
    *,
    project_name: str,
    posture: str,
    current: ProjectDecision,
    prior: ProjectDecision | None,
    suppressions: tuple[Suppression, ...],
) -> tuple[Alert, ...]:
    """Compute the set of alerts to emit for a single project.

    Pure function: takes prior + current state and the current suppression
    list, returns a deterministic alert tuple.

    Suppression expiry is detected by replaying the same suppressions list
    against two timestamps:
        - active at prior.scanned_at.date()
        - expired at current.scanned_at.date()
    No snapshotting is needed; we accept that a suppression added AFTER
    the prior scan and expiring BEFORE the current scan would not be
    detected (a degenerate edge case in practice).

    Order: quarantine first, then still_running, then suppression_expired,
    then informational. Within each category: by cve_id ascending.
    """
    prior_by_cve = _dispositions_by_cve(prior)

    quarantine_alerts: list[Alert] = []
    still_running_alerts: list[Alert] = []
    informational_alerts: list[Alert] = []

    for fd in current.findings:
        cve = fd.finding.cve_id
        prior_disp = prior_by_cve.get(cve)

        if fd.disposition == Disposition.QUARANTINE:
            # Newly QUARANTINE iff prior is missing or had a different
            # disposition (including STILL_RUNNING_AT_RISK → operator
            # disabled the exemption, which counts as a new quarantine).
            if prior_disp is None or prior_disp.disposition != Disposition.QUARANTINE:
                quarantine_alerts.append(format_quarantine_alert(current, fd))

        elif fd.disposition == Disposition.STILL_RUNNING_AT_RISK:
            if (
                prior_disp is None
                or prior_disp.disposition != Disposition.STILL_RUNNING_AT_RISK
            ):
                still_running_alerts.append(
                    format_still_running_alert(current, fd),
                )

        elif fd.disposition == Disposition.INFORMATIONAL:
            # Only alert when the CVE is genuinely new (was not in prior at
            # all). A finding that simply persisted as INFORMATIONAL is silent.
            if prior_disp is None:
                informational_alerts.append(
                    format_informational_alert(current, fd, posture),
                )

    # Suppression-expired transitions: a suppression that was active at the
    # prior scan and is no longer active at the current scan.
    suppression_expired_alerts: list[Alert] = []
    if prior is not None:
        prior_date = prior.scanned_at.date()
        current_date = current.scanned_at.date()
        for sup in suppressions:
            if sup.is_active(today=prior_date) and not sup.is_active(today=current_date):
                suppression_expired_alerts.append(
                    format_suppression_expired_alert(project_name, sup),
                )

    # Stable per-category ordering.
    quarantine_alerts.sort(key=_alert_sort_key)
    still_running_alerts.sort(key=_alert_sort_key)
    informational_alerts.sort(key=_alert_sort_key)
    suppression_expired_alerts.sort(key=_alert_sort_key)

    return tuple(
        quarantine_alerts
        + still_running_alerts
        + suppression_expired_alerts
        + informational_alerts
    )


def _alert_sort_key(alert: Alert) -> str:
    """Stable sort key — uses title, which contains the cve_id."""
    return alert.title


# ---------- delivery ----------


def _load_pushover_config(paths: BoxPaths) -> tuple[str, str]:
    """Return (user_key, app_token). Empty strings if missing or unreadable."""
    try:
        config = load_config(paths)
    except ConfigError:
        return "", ""
    pushover = config.get("pushover", {}) or {}
    return pushover.get("user_key", "") or "", pushover.get("app_token", "") or ""


def send_alerts(alerts: tuple[Alert, ...], paths: BoxPaths) -> int:
    """Send Pushover notifications for each alert. Returns count successfully sent.

    If the Pushover config is missing (no user_key / app_token), logs a
    single WARNING and returns 0 — the scan record on disk is the durable
    truth, alerts are best-effort surfacing.

    Each send is independent: a failure on one alert is logged at WARNING
    and the loop continues. Returns the count of successful sends.
    """
    if not alerts:
        return 0

    user_key, app_token = _load_pushover_config(paths)
    if not user_key or not app_token:
        _LOGGER.warning(
            "alerts skipped, pushover not configured "
            "(%d alert(s) would have been sent)",
            len(alerts),
            extra=_extra(detail={"alert_count": len(alerts)}),
        )
        return 0

    sent = 0
    for alert in alerts:
        try:
            ok = send_notification(
                user_key, app_token, alert.title, alert.body,
                priority=alert.priority,
            )
        except Exception as e:  # defensive: pushover.send_notification swallows  # noqa: BLE001
            _LOGGER.warning(
                "pushover send raised for %r: %s", alert.title, e,
                extra=_extra(detail={
                    "alert_kind": alert.kind, "title": alert.title,
                    "error": str(e),
                }),
            )
            ok = False
        if ok:
            sent += 1
        else:
            _LOGGER.warning(
                "pushover send failed for %r (kind=%s)",
                alert.title, alert.kind,
                extra=_extra(detail={
                    "alert_kind": alert.kind, "title": alert.title,
                }),
            )
    return sent


def emit_scan_alerts(
    *,
    project_name: str,
    posture: str,
    current: ProjectDecision,
    prior: ProjectDecision | None,
    suppressions: tuple[Suppression, ...],
    paths: BoxPaths,
) -> int:
    """detect_transitions + send_alerts in one call. Returns count sent."""
    alerts = detect_transitions(
        project_name=project_name,
        posture=posture,
        current=current,
        prior=prior,
        suppressions=suppressions,
    )
    return send_alerts(alerts, paths)
