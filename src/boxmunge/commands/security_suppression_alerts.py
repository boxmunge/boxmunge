# SPDX-License-Identifier: Apache-2.0
"""A run's suppression alerts: expiries, and the advance warnings.

Sent after the run's enforcement (and from a ``finally``, so a run that dies
midway still sends what its scans found), so an expiry alert says what the
expiry did: a quarantine landed, the circuit breaker held it, the site runs
at risk, it only alerts, or the project's scan failed and it was not judged.
A warning says what the expiry will do, from the scan's re-judgement without
the suppression (security_scan_evaluate.foresee).

Project scope: one alert of each kind per project, from any run that scans
it. Host scope needs every project judged, so only a full fleet run (the
nightly scan) alerts it, once per run (audit B-14). A partial run (a
single-project scan, a KEV watch tick) that finds a host suppression expired
leaves it pending in the notice record for the next full run, which judges
the whole fleet; a host expiry alert that is not delivered stays pending.

Each warning is sent once per (CVE, scope, project, until) and recorded only
once delivered (cve.suppression_record). If the record cannot be used, no
warning is sent and the caller reports the problem; a host expiry is then
alerted at once (partial if this run judged only part of the fleet) rather
than lost.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime

from boxmunge.commands.security_scan_core import ProjectScan
from boxmunge.cve.alerting import (
    Alert, format_suppression_expired_alert, format_suppression_expiring_alert,
)
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.suppression_impact import Expiry, ProjectImpact, actual_impact, not_judged
from boxmunge.cve.suppression_record import (
    HostKey, NoticeRecord, host_key, read_record, record_lock, repair_hint, warned_key,
    write_record,
)
from boxmunge.cve.suppressions import (
    SCOPE_HOST, Suppression, SuppressionsError, load_suppressions,
)
from boxmunge.log import log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

# One suppression and what it does (or will do) to each project.
_Entries = list[tuple[Suppression, list[ProjectImpact]]]


@dataclass(frozen=True)
class SuppressionRun:
    """What a run hands over: its completed scans, every expiry its scans
    found (failed ones too), the breaker's held CVEs, the projects it could
    not judge, whether it judged the whole fleet, and its clock."""

    scans: Mapping[str, ProjectScan]
    expiries: Sequence[Expiry]
    held: Mapping[str, frozenset[str]]
    unjudged: Sequence[str]
    full: bool
    today: date
    now: datetime


def _send(paths: BoxPaths, alert: Alert) -> bool:
    """Deliver one alert; True only when it was delivered (notify logs why not)."""
    try:
        return notify(paths, alert.title, alert.body, component="cve-alert",
                      priority=alert.priority)
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning("cve-scan", f"suppression alert delivery failed: {e}", paths)
        return False


def _actual(paths: BoxPaths, run: SuppressionRun, name: str, posture: str,
            decisions, cve: str) -> ProjectImpact:
    return actual_impact(name, posture, decisions, cve,
                         quarantined=is_quarantined(name, paths),
                         held=run.held.get(name, frozenset()))


def _fleet_impacts(paths: BoxPaths, run: SuppressionRun, cve: str) -> list[ProjectImpact]:
    """``cve``'s outcome on every project the run scanned, and the rest unjudged."""
    out = [_actual(paths, run, name, scan.posture, scan.decisions, cve)
           for name, scan in sorted(run.scans.items())]
    return out + [not_judged(name) for name in sorted(set(run.unjudged))]


def _project_expiries(paths: BoxPaths, run: SuppressionRun) -> list[Alert]:
    alerts = []
    for exp in sorted(run.expiries, key=lambda e: e.project):
        own = [s for s in exp.suppressions if s.scope != SCOPE_HOST]
        if own:
            alerts.append(format_suppression_expired_alert([
                (s, [not_judged(exp.project, exp.posture) if exp.failed else
                     _actual(paths, run, exp.project, exp.posture, exp.decisions, s.cve_id)])
                for s in own], project=exp.project))
    return alerts


def _host_detected(run: SuppressionRun) -> dict[HostKey, Suppression]:
    return {host_key(s): s for exp in run.expiries for s in exp.suppressions
            if s.scope == SCOPE_HOST}


def _host_alert(paths: BoxPaths, run: SuppressionRun,
                sups: Mapping[HostKey, Suppression], *, partial: bool) -> Alert:
    entries: _Entries = [(s, _fleet_impacts(paths, run, s.cve_id)) for s in sups.values()]
    return format_suppression_expired_alert(entries, project=None, partial=partial)


def _pending_suppressions(paths: BoxPaths, pending: set[HostKey]) -> dict[HostKey, Suppression]:
    """The pending host expiries still in the host file (one the operator
    has since removed or replaced is dropped: there is nothing to alert)."""
    if not pending:
        return {}
    try:
        listed = {host_key(s): s for s in load_suppressions(
            paths.host_suppressions, scope=SCOPE_HOST)}
    except SuppressionsError as e:
        # The scans fail on the same file; keep the entries for a later run.
        log_warning("cve-scan", f"pending host suppression expiries kept: {e}", paths)
        return {}
    for key in sorted(pending - set(listed)):
        log_operation("cve-alert", f"host suppression {key[0]} (until {key[1]}) is no "
                      f"longer in the host file; its pending expiry alert is dropped", paths)
        pending.discard(key)
    return {k: listed[k] for k in pending}


def _host_expiries(paths: BoxPaths, run: SuppressionRun, record: NoticeRecord) -> bool:
    """Alert (full run) or leave pending (partial run) the host expiries.
    True when a host expiry alert was delivered."""
    detected = _host_detected(run)
    if not run.full:
        for key in sorted(set(detected) - record.pending):
            log_operation("cve-alert", f"host suppression {key[0]} expired; the nightly "
                          f"fleet scan alerts it with every project judged", paths)
        record.pending |= set(detected)
        return False
    sups = {**_pending_suppressions(paths, record.pending), **detected}
    if not sups:
        return False
    if _send(paths, _host_alert(paths, run, sups, partial=False)):
        record.pending -= set(sups)
        return True
    record.pending |= set(sups)
    return False


def _warnings(run: SuppressionRun, record: NoticeRecord) -> list[tuple[Alert, list]]:
    """The warnings not yet delivered, each with the keys it covers."""
    host: dict[HostKey, tuple[Suppression, list[ProjectImpact]]] = {}
    planned: list[tuple[Alert, list]] = []
    for name in sorted(run.scans):
        own: dict[HostKey, tuple[Suppression, list[ProjectImpact]]] = {}
        for item in run.scans[name].expiring:
            sup = item.suppression
            if warned_key(sup, name) in record.warned:
                continue
            if sup.scope != SCOPE_HOST:
                own.setdefault(host_key(sup), (sup, []))[1].append(item.impact)
            elif run.full:
                host.setdefault(host_key(sup), (sup, []))[1].append(item.impact)
        if own:
            planned.append((format_suppression_expiring_alert(
                list(own.values()), project=name, now=run.now),
                [warned_key(s, name) for s, _ in own.values()]))
    if host:
        for sup, impacts in host.values():
            impacts += [not_judged(n) for n in sorted(set(run.unjudged))]
        planned.insert(0, (format_suppression_expiring_alert(
            list(host.values()), project=None, now=run.now),
            [warned_key(s, "") for s, _ in host.values()]))
    return planned


def send_suppression_alerts(paths: BoxPaths, run: SuppressionRun) -> str | None:
    """Send the run's suppression alerts. Returns why the notice record could
    not be used, or None. The caller reports it and fails the run."""
    for alert in _project_expiries(paths, run):
        _send(paths, alert)
    if not (run.full or _host_detected(run) or any(s.expiring for s in run.scans.values())):
        return None
    host_handled = False
    try:
        with record_lock(paths):
            record = read_record(paths)
            host_handled = _host_expiries(paths, run, record)
            for alert, keys in _warnings(run, record):
                if _send(paths, alert):
                    record.warned.update((k, run.now) for k in keys)
            write_record(paths, record, run.today)
            host_handled = True
    except StateError as e:
        if not host_handled and _host_detected(run):
            _send(paths, _host_alert(paths, run, _host_detected(run), partial=not run.full))
        return f"{e}; {repair_hint(paths)}"
    return None
