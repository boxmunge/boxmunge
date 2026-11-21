# SPDX-License-Identifier: Apache-2.0
"""cve.suppression_impact: the warning window and the outcome classes."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from boxmunge.cve.exploited import ExploitedSource
from boxmunge.cve.policy import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.scanner import Finding, Severity
from boxmunge.cve.suppression_impact import (
    MAX_RUN_GAP, WARN_BEFORE, Impact, actual_impact, expires_at, foreseen_impact,
    in_warning_window, suppressions_at_expiry,
)
from boxmunge.cve.suppressions import SCOPE_HOST, Suppression

CVE = "CVE-2026-57433"
UNTIL = date(2026, 11, 23)


def _sup(until: date = UNTIL, cve: str = CVE, scope: str = SCOPE_HOST) -> Suppression:
    return Suppression(cve, until, "r", "ops", date(2026, 8, 25), scope=scope)


def _fd(disposition: Disposition, *, package: str = "perl", fix: str | None = None,
        exploited=frozenset(), kev_override: bool = False) -> FindingDisposition:
    finding = Finding(cve_id=CVE, severity=Severity.HIGH, package=package,
                      installed_version="1", fixed_version=fix, title="", primary_url=None)
    return FindingDisposition(finding, Severity.HIGH, 0, Severity.HIGH, disposition, None, "",
                              exploited_by=exploited, kev_override=kev_override)


def _decisions(*fds: FindingDisposition) -> tuple[ProjectDecision, ...]:
    return (ProjectDecision("shop", "shop-web:1", fds, False, False,
                            datetime(2026, 11, 21, 3, tzinfo=timezone.utc)),)


def _at(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 11, day, hour, minute, tzinfo=timezone.utc)


@pytest.mark.parametrize(("now", "inside"), [
    (_at(20, 19, 59), False),   # 52h01m out
    (_at(20, 20), True),        # exactly WARN_BEFORE (52h)
    (_at(21, 2, 30), True),     # a nightly at 02:30 UTC two days before
    (_at(22, 23, 30), True),    # a missed night: the next run still warns
])
def test_warning_window_edges(now, inside) -> None:
    assert WARN_BEFORE == timedelta(hours=52)
    assert in_warning_window(_sup(), today=now.date(), now=now) is inside


def test_expired_is_never_in_the_window() -> None:
    assert not in_warning_window(_sup(), today=UNTIL, now=_at(23, 0, 1))


def test_first_run_in_the_window_is_at_least_24h_ahead() -> None:
    """A run just outside the window; the next, at most MAX_RUN_GAP later
    (timer, jitter, DST, a KEV watch wait), is in it with >= 24h left."""
    previous = expires_at(_sup()) - WARN_BEFORE - timedelta(minutes=1)
    assert not in_warning_window(_sup(), today=previous.date(), now=previous)
    nxt = previous + MAX_RUN_GAP
    assert in_warning_window(_sup(), today=nxt.date(), now=nxt)
    assert expires_at(_sup()) - nxt > timedelta(hours=24)


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
    current = _decisions(_fd(Disposition.SUPPRESSED))
    got = foreseen_impact("shop", "strict", _decisions(_fd(disposition)), current, CVE)
    assert got.impact is impact


def test_a_suppression_already_not_applying_changes_nothing() -> None:
    """A known-exploited listing overrides it: the scan did not suppress the
    finding, so the expiry is not a quarantine to warn of."""
    listed = _fd(Disposition.QUARANTINE, exploited=frozenset({ExploitedSource.VULNCHECK}),
                 kev_override=True)
    got = foreseen_impact("shop", "paranoid", _decisions(listed), _decisions(listed), CVE)
    assert got.impact is Impact.NOT_APPLYING


def test_foreseen_no_finding_and_worst_package_decides() -> None:
    none = foreseen_impact("shop", "balanced", _decisions(), _decisions(), CVE)
    assert none.impact is Impact.NO_FINDING
    mixed = _decisions(_fd(Disposition.INFORMATIONAL, package="perl-base"),
                       _fd(Disposition.QUARANTINE, package="libperl"))
    current = _decisions(_fd(Disposition.SUPPRESSED, package="perl-base"),
                         _fd(Disposition.SUPPRESSED, package="libperl"))
    assert foreseen_impact("shop", "paranoid", mixed, current, CVE).impact is Impact.QUARANTINED


def test_facts_name_kev_and_fix() -> None:
    fd = _fd(Disposition.QUARANTINE, fix="2",
             exploited=frozenset({ExploitedSource.VULNCHECK}))
    impact = foreseen_impact("shop", "paranoid", _decisions(fd),
                             _decisions(_fd(Disposition.SUPPRESSED)), CVE)
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


def test_actual_alert_only() -> None:
    got = actual_impact("blog", "balanced", _decisions(_fd(Disposition.AWAITING_FIX)), CVE,
                        quarantined=False, held=frozenset({CVE}))
    assert got.impact is Impact.ALERT


@pytest.mark.parametrize("disposition", [Disposition.AWAITING_FIX,
                                         Disposition.STILL_RUNNING_AT_RISK])
def test_actual_already_quarantined_for_another_finding(disposition) -> None:
    got = actual_impact("blog", "balanced", _decisions(_fd(disposition)), CVE,
                        quarantined=True, held=frozenset())
    assert got.impact is Impact.ALREADY_QUARANTINED


def test_a_suppressed_fixable_finding_is_not_mistaken_for_an_override() -> None:
    """The policy checks the fix before the suppression: a suppressed
    fixable finding is IGNORED_FIXED, and its expiry can still quarantine."""
    current = _decisions(_fd(Disposition.IGNORED_FIXED, fix="2"))
    foreseen = _decisions(_fd(Disposition.QUARANTINE, fix="2"))
    got = foreseen_impact("shop", "paranoid", foreseen, current, CVE)
    assert got.impact is Impact.QUARANTINED
