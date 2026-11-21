# SPDX-License-Identifier: Apache-2.0
"""cve.suppression_impact: the warning window and the outcome classes."""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from boxmunge.cve.exploited import ExploitedSource
from boxmunge.cve.policy import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.scanner import Finding, Severity
from boxmunge.cve.suppression_impact import (
    WARN_DAYS, Impact, actual_impact, foreseen_impact, in_warning_window,
    suppressions_at_expiry,
)
from boxmunge.cve.suppressions import SCOPE_HOST, Suppression

CVE = "CVE-2026-57433"
UNTIL = date(2026, 11, 23)


def _sup(until: date = UNTIL, cve: str = CVE, scope: str = SCOPE_HOST) -> Suppression:
    return Suppression(cve, until, "r", "ops", date(2026, 8, 25), scope=scope)


def _fd(disposition: Disposition, *, package: str = "perl", fix: str | None = None,
        exploited=frozenset()) -> FindingDisposition:
    finding = Finding(cve_id=CVE, severity=Severity.HIGH, package=package,
                      installed_version="1", fixed_version=fix, title="", primary_url=None)
    return FindingDisposition(finding, Severity.HIGH, 0, Severity.HIGH, disposition, None, "",
                              exploited_by=exploited)


def _decisions(*fds: FindingDisposition) -> tuple[ProjectDecision, ...]:
    return (ProjectDecision("shop", "shop-web:1", fds, False, False,
                            datetime(2026, 11, 21, 3, tzinfo=timezone.utc)),)


@pytest.mark.parametrize(("today", "inside"), [
    (date(2026, 11, 20), False),   # 3 days out: the next scan is still > 24h ahead
    (date(2026, 11, 21), True),    # the scan on until-2 (UTC): 24-48h ahead
    (date(2026, 11, 22), True),    # a missed until-2 scan: the next one still warns
    (date(2026, 11, 23), False),   # expired: the expiry alert's turn
])
def test_warning_window_edges(today, inside) -> None:
    assert WARN_DAYS == 2
    assert in_warning_window(_sup(), today) is inside


def test_suppressions_at_expiry_drop_everything_gone_by_then() -> None:
    sooner, same, later = _sup(date(2026, 11, 22)), _sup(), _sup(date(2026, 12, 1))
    assert suppressions_at_expiry((sooner, same, later), UNTIL) == (later,)


@pytest.mark.parametrize(("disposition", "impact"), [
    (Disposition.QUARANTINE, Impact.QUARANTINED),
    (Disposition.STILL_RUNNING_AT_RISK, Impact.AT_RISK),
    (Disposition.AWAITING_FIX, Impact.ALERT),
    (Disposition.INFORMATIONAL, Impact.ALERT),
    (Disposition.IGNORED_FIXED, Impact.ALERT),
    (Disposition.SUPPRESSED, Impact.SUPPRESSED),
])
def test_foreseen_classes(disposition, impact) -> None:
    assert foreseen_impact("shop", "strict", _decisions(_fd(disposition)), CVE).impact is impact


def test_foreseen_no_finding_and_worst_package_decides() -> None:
    assert foreseen_impact("shop", "balanced", _decisions(), CVE).impact is Impact.NO_FINDING
    mixed = _decisions(_fd(Disposition.INFORMATIONAL, package="perl-base"),
                       _fd(Disposition.QUARANTINE, package="libperl"))
    assert foreseen_impact("shop", "paranoid", mixed, CVE).impact is Impact.QUARANTINED


def test_facts_name_kev_and_fix() -> None:
    fd = _fd(Disposition.QUARANTINE, fix="2",
             exploited=frozenset({ExploitedSource.VULNCHECK}))
    impact = foreseen_impact("shop", "paranoid", _decisions(fd), CVE)
    assert impact.facts == ("known exploited (VulnCheck KEV)", "fix available")


@pytest.mark.parametrize(("quarantined", "held", "impact"), [
    (True, frozenset(), Impact.QUARANTINED),
    (False, frozenset({CVE}), Impact.HELD),
    # Quarantine-level but up: an urgent autofix, or a failed stop.
    (False, frozenset(), Impact.AT_RISK),
])
def test_actual_quarantine_outcomes(quarantined, held, impact) -> None:
    got = actual_impact("shop", "paranoid", _decisions(_fd(Disposition.QUARANTINE)), CVE,
                        quarantined=quarantined, held=held)
    assert got.impact is impact


def test_actual_alert_only_ignores_enforcement_state() -> None:
    got = actual_impact("blog", "balanced", _decisions(_fd(Disposition.AWAITING_FIX)), CVE,
                        quarantined=True, held=frozenset({CVE}))
    assert got.impact is Impact.ALERT
