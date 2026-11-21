# SPDX-License-Identifier: Apache-2.0
"""A fleet run's suppression alerts: expiries, and the advance warnings.

Built after the run's enforcement (security_actions._alert_fleet), so an
expiry alert says what the expiry did: a quarantine landed, the circuit
breaker held it, the site runs at risk, or it only alerts. A warning says
what the expiry will do, from the scan's re-judgement without the
suppression (security_scan_evaluate.foresee).

Host scope is one alert of each kind per run (audit B-14). The host
warning needs every project judged, so only a full fleet run (the nightly
scan, ``host_warnings``) sends it; a single-project scan or a KEV watch tick
sees part of the fleet and leaves it to that run. Project scope is one alert
of each kind per project, from any scan of it.

Each warning is sent once per (CVE, scope, project, until), recorded in
cve.suppression_warned.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from boxmunge.commands.security_scan_core import ProjectScan
from boxmunge.cve.alerting import (
    Alert, format_suppression_expired_alert, format_suppression_expiring_alert,
)
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.suppression_impact import ProjectImpact, actual_impact
from boxmunge.cve.suppression_warned import Key, read_warned, warned_key, write_warned
from boxmunge.cve.suppressions import SCOPE_HOST, Suppression
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

# One suppression and what it does (or will do) to each project.
_Grouped = dict[tuple[str, str], tuple[Suppression, list[ProjectImpact]]]


def _add(groups: _Grouped, sup: Suppression, impact: ProjectImpact) -> None:
    groups.setdefault((sup.cve_id, sup.until.isoformat()), (sup, []))[1].append(impact)


def _expired_alerts(
    paths: BoxPaths, scans: Mapping[str, ProjectScan],
    held: Mapping[str, frozenset[str]],
) -> list[Alert]:
    host: _Grouped = {}
    alerts: list[Alert] = []
    for name in sorted(scans):
        scan = scans[name]
        if not scan.expired:
            continue
        quarantined = is_quarantined(name, paths)
        own: _Grouped = {}
        for sup in scan.expired:
            impact = actual_impact(name, scan.posture, scan.decisions, sup.cve_id,
                                   quarantined=quarantined, held=held.get(name, frozenset()))
            _add(host if sup.scope == SCOPE_HOST else own, sup, impact)
        if own:
            alerts.append(format_suppression_expired_alert(list(own.values()), project=name))
    if host:
        alerts.insert(0, format_suppression_expired_alert(list(host.values()), project=None))
    return alerts


def _warning_alerts(
    scans: Mapping[str, ProjectScan], warned: dict[Key, datetime], *,
    now: datetime, host_warnings: bool, unscanned: Sequence[str],
) -> list[Alert]:
    """The warnings not yet sent; marks each sent in ``warned``."""
    host: _Grouped = {}
    alerts: list[Alert] = []
    for name in sorted(scans):
        own: _Grouped = {}
        for item in scans[name].expiring:
            sup = item.suppression
            if warned_key(sup, name) in warned:
                continue
            if sup.scope != SCOPE_HOST:
                _add(own, sup, item.impact)
            elif host_warnings:
                _add(host, sup, item.impact)
        if own:
            alerts.append(format_suppression_expiring_alert(
                list(own.values()), project=name, now=now))
            for sup, _ in own.values():
                warned[warned_key(sup, name)] = now
    if host:
        alerts.insert(0, format_suppression_expiring_alert(
            list(host.values()), project=None, now=now, unscanned=unscanned))
        for sup, _ in host.values():
            warned[warned_key(sup, "")] = now
    return alerts


def suppression_alerts(
    paths: BoxPaths, scans: Mapping[str, ProjectScan],
    held: Mapping[str, frozenset[str]], *, now: datetime, host_warnings: bool,
    unscanned: Sequence[str] = (),
) -> tuple[list[Alert], str | None]:
    """The run's suppression alerts, and why the warning record could not be
    used (None when it could). An unusable record sends no warning, so none
    repeats every scan; the caller reports it as a problem of the run. The
    warnings are recorded as sent before delivery, like strict's fix
    deadline: delivery is best effort and logs every failure."""
    alerts = _expired_alerts(paths, scans, held)
    if not any(scan.expiring for scan in scans.values()):
        return alerts, None
    try:
        warned = read_warned(paths)
        before = dict(warned)
        warnings = _warning_alerts(scans, warned, now=now, host_warnings=host_warnings,
                                   unscanned=unscanned)
        if warned != before:
            write_warned(paths, warned, now.date())
    except StateError as e:
        return alerts, f"suppression expiry warnings not sent: {e}"
    return alerts + warnings, None
