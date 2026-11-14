# SPDX-License-Identifier: Apache-2.0
"""Pushover alerting for CVE policy state transitions.

This module turns a project's prior and current scan decisions plus the
current suppression list into a handful of Alerts and pushes them through
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
* No spam (audit B-13, B-14) — a finding is identified by (CVE, package)
  across all of the project's images, never by image digest, so an image
  rebuild with an unchanged finding set alerts nothing, and one CVE with
  different dispositions in two packages is two stable findings rather
  than one flapping one. Each kind of transition produces at most ONE
  alert per project per scan, listing every finding involved. Recovery
  (good news) is not alerted.

Module layout
-------------
* ``Alert`` / ``AlertKind`` / ``Hit`` live in ``_alerting_types``.
* Fleet digest (``_alerting_digest``): the low-urgency kinds are not sent
  per project. A fleet scan collects them and sends ONE quiet digest; urgent
  kinds are always immediate. At relaxed and balanced the purely
  informational new-findings alert is dropped (still in ``security status``
  and the log): those postures only act on what needs acting on.
* Per-project formatters live in ``_alerting_formatters``; fleet-level
  ones (KEV, scan failure, host suppression expiry) in
  ``_alerting_fleet``. Both are re-exported here.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from boxmunge.cve._alerting_fleet import (
    format_breaker_held_alert,
    format_host_suppression_expired_alert,
    format_kev_sources_disagree_alert,
    format_kev_stale_alert,
    format_kev_withdrawn_alert,
    format_scan_failure_alert,
    format_scan_unrecorded_alert,
)
from boxmunge.cve._alerting_formatters import (
    format_awaiting_fix_alert,
    format_fixable_alert,
    format_hardening_upcoming_alert,
    format_kev_at_risk_alert,
    format_kev_fix_pending_alert,
    format_kev_withdrawal_hold_alert,
    format_new_findings_alert,
    format_quarantine_alert,
    format_quarantine_lifted_alert,
    format_still_running_alert,
    format_suppression_expired_alert,
    lift_reason,
)
from boxmunge.cve._alerting_types import Alert, AlertKind, Hit
from boxmunge.cve._alerting_digest import (
    format_scan_digest,
    is_low_urgency,
)
from boxmunge.cve.policy import Disposition, Posture, ProjectDecision
from boxmunge.cve.suppressions import SCOPE_HOST, Suppression
from boxmunge.log import log_operation
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths

__all__ = [
    "Alert",
    "AlertKind",
    "Hit",
    "Transitions",
    "format_quarantine_alert",
    "format_quarantine_lifted_alert",
    "format_kev_withdrawal_hold_alert",
    "lift_reason",
    "format_still_running_alert",
    "format_new_findings_alert",
    "format_kev_fix_pending_alert",
    "format_kev_at_risk_alert",
    "format_awaiting_fix_alert",
    "format_fixable_alert",
    "format_hardening_upcoming_alert",
    "format_suppression_expired_alert",
    "format_host_suppression_expired_alert",
    "format_breaker_held_alert",
    "format_kev_sources_disagree_alert",
    "format_kev_stale_alert",
    "format_kev_withdrawn_alert",
    "format_scan_failure_alert",
    "format_scan_unrecorded_alert",
    "detect_transitions",
    "format_scan_digest",
    "is_low_urgency",
    "send_alerts",
    "emit_scan_alerts",
]


_LOGGER = logging.getLogger("boxmunge")

# Which disposition represents a (CVE, package) seen in several images.
_DISPOSITION_RANK = {
    Disposition.QUARANTINE: 5,
    Disposition.STILL_RUNNING_AT_RISK: 4,
    Disposition.AWAITING_FIX: 3,
    Disposition.INFORMATIONAL: 2,
    Disposition.SUPPRESSED: 1,
    Disposition.IGNORED_FIXED: 0,
}


def _extra(
    project: str | None = None, detail: dict | None = None,
) -> dict:
    """Structured-extras helper for cve-alert events."""
    return {"component": "cve-alert", "project": project, "detail": detail}


# ---------- transition detection ----------


@dataclass(frozen=True)
class Transitions:
    """Alerts for one project, plus the host-scope suppressions that
    expired — those are alerted once per fleet run by the caller."""

    alerts: tuple[Alert, ...]
    host_expired: tuple[Suppression, ...] = ()
    # Informational alerts this posture does not send (logged by the caller).
    dropped: tuple[Alert, ...] = ()


# Postures at or below balanced act only on what needs acting on: a finding
# below the gate with no change to make is not worth a push.
_QUIET_INFORMATIONAL = frozenset({Posture.RELAXED, Posture.BALANCED})


def findings_by_key(
    decisions: Sequence[ProjectDecision],
) -> dict[tuple[str, str], Hit]:
    """(cve_id, package) → the most severe disposition across all images."""
    out: dict[tuple[str, str], Hit] = {}
    for decision in decisions:
        for fd in decision.findings:
            key = (fd.finding.cve_id, fd.finding.package)
            held = out.get(key)
            if held is None or (
                _DISPOSITION_RANK[fd.disposition]
                > _DISPOSITION_RANK[held.disposition.disposition]
            ):
                out[key] = Hit(fd, decision.image_ref)
    return out


def hardening_upcoming_by_key(
    decisions: Sequence[ProjectDecision],
) -> dict[tuple[str, str], Hit]:
    """(cve_id, package) → a finding flagged hardening_would_quarantine."""
    return {
        (fd.finding.cve_id, fd.finding.package): Hit(fd, decision.image_ref)
        for decision in decisions for fd in decision.findings
        if fd.hardening_would_quarantine
    }


def _scan_date(decisions: Sequence[ProjectDecision]) -> date | None:
    if not decisions:
        return None
    return max(d.scanned_at for d in decisions).date()


def detect_transitions(
    *,
    project_name: str,
    posture: Posture,
    current: Sequence[ProjectDecision],
    prior: Sequence[ProjectDecision],
    suppressions: tuple[Suppression, ...],
) -> Transitions:
    """Compute this project's alerts from its prior and current decisions.

    Pure. A finding transitions when its (CVE, package) key is new or its
    disposition changed. Suppression expiry is detected by replaying the
    suppression list against the prior and current scan dates.

    QUARANTINE dispositions are not alerted here: the QUARANTINED alert is
    tied to the quarantine action landing (audit B-17), which the
    enforcement step announces.

    A KEV finding left running — opted out of quarantine (B-09), or
    fixable under relaxed (B-01) — is alerted on EVERY scan, not only on a
    transition.

    A finding that quarantines from 0.12 but not now (hardening_would_quarantine)
    is warned once, when it first carries the flag.

    An AWAITING_FIX finding (balanced: no fix yet, not exploited) is alerted
    once, when it enters that disposition, never again while it stays there:
    nothing needs doing. Its next alert is the change — a fix landing (the
    fix_available alert, with the rebuild advice) or a KEV listing (the
    quarantine alert).

    At relaxed and balanced the informational (new below-the-gate findings)
    alert is dropped into ``Transitions.dropped``; awaiting_fix, fixable and
    hardening_upcoming are kept, as they name a change the operator may act on.

    Order: kev_at_risk, kev_fix_pending, still_running, suppression_expired,
    fix_available, awaiting_fix, hardening_upcoming, informational.
    """
    before = findings_by_key(prior)
    now = findings_by_key(current)
    new_at_risk: list[Hit] = []
    new_info: list[Hit] = []
    new_fixable: list[Hit] = []
    new_awaiting: list[Hit] = []
    # Standing, not transitions: alerted on every scan while live (B-01, B-09).
    kev_fix_pending: list[Hit] = []
    kev_at_risk: list[Hit] = []
    for key, hit in now.items():
        fd = hit.disposition
        disp = fd.disposition
        old = before.get(key)
        changed = old is None or old.disposition.disposition != disp
        if disp == Disposition.IGNORED_FIXED and fd.kev_listed:
            kev_fix_pending.append(hit)
        elif disp == Disposition.STILL_RUNNING_AT_RISK and fd.kev_listed:
            kev_at_risk.append(hit)
        elif disp == Disposition.IGNORED_FIXED and fd.fix_would_quarantine and (
            changed or not old.disposition.fix_would_quarantine
        ):
            new_fixable.append(hit)
        elif disp == Disposition.STILL_RUNNING_AT_RISK and changed:
            new_at_risk.append(hit)
        elif disp == Disposition.AWAITING_FIX and changed:
            new_awaiting.append(hit)
        elif disp in (Disposition.INFORMATIONAL, Disposition.IGNORED_FIXED) and old is None:
            # A new below-gate finding, fixable or not, is still reported;
            # one that quarantines from 0.12 has its own warning below.
            if not fd.hardening_would_quarantine:
                new_info.append(hit)

    # One warning per project per finding: only keys not already flagged.
    flagged_before = hardening_upcoming_by_key(prior)
    new_upcoming = [h for k, h in hardening_upcoming_by_key(current).items()
                    if k not in flagged_before]

    project_expired: list[Suppression] = []
    host_expired: list[Suppression] = []
    prior_date, current_date = _scan_date(prior), _scan_date(current)
    if prior_date is not None and current_date is not None:
        for sup in suppressions:
            if sup.is_active(today=prior_date) and not sup.is_active(today=current_date):
                (host_expired if sup.scope == SCOPE_HOST else project_expired).append(sup)

    alerts: list[Alert] = []
    dropped: list[Alert] = []
    if kev_at_risk:
        alerts.append(format_kev_at_risk_alert(project_name, kev_at_risk))
    if kev_fix_pending:
        alerts.append(format_kev_fix_pending_alert(project_name, kev_fix_pending))
    if new_at_risk:
        alerts.append(format_still_running_alert(project_name, new_at_risk))
    if project_expired:
        alerts.append(format_suppression_expired_alert(project_name, project_expired))
    if new_fixable:
        alerts.append(format_fixable_alert(project_name, new_fixable))
    if new_awaiting:
        alerts.append(format_awaiting_fix_alert(project_name, new_awaiting))
    if new_upcoming:
        alerts.append(format_hardening_upcoming_alert(project_name, new_upcoming))
    if new_info:
        info = format_new_findings_alert(project_name, new_info)
        (dropped if posture in _QUIET_INFORMATIONAL else alerts).append(info)
    return Transitions(alerts=tuple(alerts), host_expired=tuple(host_expired),
                       dropped=tuple(dropped))


# ---------- delivery ----------


def send_alerts(alerts: tuple[Alert, ...], paths: BoxPaths) -> int:
    """Send each alert through ``boxmunge.notify``. Returns how many were
    delivered.

    ``notify`` logs every non-delivery (Pushover unconfigured, config
    unreadable, API failure), so an undelivered alert is never silent.
    Callers that record "alert sent" state do so only for delivered alerts.
    """
    return sum(
        notify(paths, alert.title, alert.body, component="cve-alert",
               priority=alert.priority)
        for alert in alerts
    )


def emit_scan_alerts(
    *,
    project_name: str,
    posture: Posture,
    current: Sequence[ProjectDecision],
    prior: Sequence[ProjectDecision],
    suppressions: tuple[Suppression, ...],
    paths: BoxPaths,
) -> Transitions:
    """detect_transitions for one project, with nothing sent.

    The caller owns delivery: a fleet scan sends the urgent alerts at once
    and batches the low-urgency ones into one digest. Alerts the posture
    drops are logged here, so the finding stays visible.
    """
    transitions = detect_transitions(
        project_name=project_name,
        posture=posture,
        current=current,
        prior=prior,
        suppressions=suppressions,
    )
    for alert in transitions.dropped:
        log_operation(
            "cve-alert",
            f"not alerted at {posture.value} posture: {alert.title}",
            paths, project=project_name,
            detail={"kind": alert.kind, "findings": len(alert.hits)},
        )
    return transitions
