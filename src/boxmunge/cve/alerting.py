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

Module layout
-------------
* The ``Alert`` / ``AlertKind`` dataclasses live in ``_alerting_types``
  so the formatter module can import them without a cycle.
* The per-disposition body formatters and the grace-heads-up formatter
  live in ``_alerting_formatters``; they're re-exported from this module
  so existing callers keep importing from ``boxmunge.cve.alerting``.

Follow-ups
----------
* Priority 2 (Pushover emergency-ack with retry/expire) is intentionally
  out of scope for v0.6.0. It would require extending pushover.py with the
  retry/expire parameters; until then, the four critical-tier categories
  use priority 1 (high-priority — bypasses the user's quiet hours).
"""

from __future__ import annotations

import logging

from boxmunge.config import ConfigError, load_config
from boxmunge.cve._alerting_formatters import (
    format_grace_heads_up_alert,
    format_informational_alert,
    format_quarantine_alert,
    format_still_running_alert,
    format_suppression_expired_alert,
)
from boxmunge.cve._alerting_types import Alert, AlertKind
from boxmunge.cve.policy import (
    Disposition,
    FindingDisposition,
    ProjectDecision,
)
from boxmunge.cve.suppressions import Suppression
from boxmunge.paths import BoxPaths
from boxmunge.pushover import send_notification


# Re-export for callers that import from boxmunge.cve.alerting.
__all__ = [
    "Alert",
    "AlertKind",
    "format_quarantine_alert",
    "format_still_running_alert",
    "format_informational_alert",
    "format_suppression_expired_alert",
    "format_grace_heads_up_alert",
    "detect_transitions",
    "send_alerts",
    "emit_scan_alerts",
]


_LOGGER = logging.getLogger("boxmunge")


def _extra(
    project: str | None = None, detail: dict | None = None,
) -> dict:
    """Structured-extras helper for cve-alert events."""
    return {"component": "cve-alert", "project": project, "detail": detail}


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
