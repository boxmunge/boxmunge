# SPDX-License-Identifier: Apache-2.0
"""Suppression expiry alert text: grouping, headline, priority, actions."""
from __future__ import annotations

from datetime import date, datetime, timezone

from boxmunge.cve.alerting import (
    format_suppression_expired_alert, format_suppression_expiring_alert,
)
from boxmunge.cve.suppression_impact import Impact, ProjectImpact
from boxmunge.cve.suppressions import SCOPE_HOST, Suppression

NOW = datetime(2026, 11, 21, 2, 47, tzinfo=timezone.utc)


def _sup(cve: str = "CVE-2026-57433", until: date = date(2026, 11, 23),
         scope: str = SCOPE_HOST) -> Suppression:
    return Suppression(cve, until, "perl unreachable", "ops", date(2026, 8, 25), scope=scope)


def _p(name: str, impact: Impact, posture: str = "balanced", facts=()) -> ProjectImpact:
    return ProjectImpact(name, posture, impact, tuple(facts))


def test_host_warning_groups_by_outcome_with_worst_in_title() -> None:
    impacts = [_p("shop", Impact.QUARANTINED, "paranoid", ["fix available"]),
               _p("api", Impact.QUARANTINED, "strict"),
               _p("blog", Impact.ALERT), _p("wiki", Impact.ALERT), _p("docs", Impact.ALERT),
               _p("legacy", Impact.AT_RISK, "strict"),
               *(_p(f"site{i}", Impact.NO_FINDING) for i in range(4))]
    alert = format_suppression_expiring_alert([(_sup(), impacts)], project=None, now=NOW,
                                              unscanned=["old"])
    assert alert.kind == "suppression_expiring" and alert.priority == 1
    assert alert.title == ("CVE-2026-57433 host suppression expires in 45h — "
                           "2 projects will be quarantined")
    body = alert.body
    assert "stops applying 2026-11-23 00:00 UTC (in 45h)" in body
    assert ("- 2 projects will be quarantined (stopped): api [strict], "
            "shop [paranoid; fix available]") in body
    assert ("- 1 project will keep running at quarantine level (quarantine disabled by "
            "config): legacy [strict]") in body
    assert "- 3 projects will alert only and keep running: blog [balanced], docs" in body
    assert "- 4 projects have no finding for it (no effect)" in body
    assert "site0" not in body
    assert "Not scanned this run, so not judged: old" in body
    assert "boxmunge security unsuppress CVE-2026-57433 --host" in body
    assert "boxmunge security suppress CVE-2026-57433 --host --until <date>" in body
    assert "operator only" in body and "Review: boxmunge security <project>" in body
    assert "added 2026-08-25 by ops: perl unreachable" in body


def test_alert_only_warning_is_normal_priority() -> None:
    alert = format_suppression_expiring_alert(
        [(_sup(), [_p("blog", Impact.ALERT), _p("wiki", Impact.NO_FINDING)])],
        project=None, now=NOW)
    assert alert.priority == 0
    assert alert.title.endswith("— 1 project will alert only")


def test_many_projects_are_capped() -> None:
    impacts = [_p(f"p{i:02d}", Impact.ALERT) for i in range(13)]
    alert = format_suppression_expiring_alert([(_sup(), impacts)], project=None, now=NOW)
    assert "p09 [balanced] (+3 more)" in alert.body and "p10" not in alert.body


def test_several_cves_share_one_host_alert() -> None:
    entries = [(_sup("CVE-2026-2"), [_p("blog", Impact.ALERT)]),
               (_sup("CVE-2026-1"), [_p("shop", Impact.QUARANTINED, "paranoid")])]
    alert = format_suppression_expiring_alert(entries, project=None, now=NOW)
    assert alert.title == ("CVE-2026-1 (+1 more) host suppressions expire in 45h — "
                           "1 project will be quarantined")
    assert alert.body.index("CVE-2026-1:") < alert.body.index("CVE-2026-2:")


def test_project_warning_names_the_project_command() -> None:
    sup = _sup(until=date(2026, 11, 22), scope="project")
    alert = format_suppression_expiring_alert(
        [(sup, [_p("shop", Impact.QUARANTINED, "strict",
                   ["known exploited (VulnCheck KEV)"])])], project="shop",
        now=datetime(2026, 11, 21, 23, 30, tzinfo=timezone.utc))
    assert alert.title == ("[boxmunge:shop] CVE-2026-57433 project suppression expires "
                           "in under an hour — will be quarantined")
    assert "- shop [strict; known exploited (VulnCheck KEV)] will be quarantined" in alert.body
    assert "suppress CVE-2026-57433 --project shop --until <date>" in alert.body
    assert "Review: boxmunge security shop" in alert.body


def test_expired_says_what_happened() -> None:
    impacts = [_p("shop", Impact.QUARANTINED, "paranoid"), _p("api", Impact.HELD, "strict"),
               _p("blog", Impact.ALERT), _p("wiki", Impact.NO_FINDING)]
    alert = format_suppression_expired_alert([(_sup(), impacts)], project=None)
    assert alert.kind == "suppression_expired" and alert.priority == 1
    assert alert.title == "CVE-2026-57433 host suppression expired — 1 project quarantined"
    assert "- 1 project is quarantined (stopped): shop [paranoid]" in alert.body
    assert "- 1 project is held by the circuit breaker, still running: api [strict]" in alert.body
    assert "- 1 project alerts only and keeps running: blog [balanced]" in alert.body
    assert "- 1 project has no finding for it (no effect)" in alert.body
    assert "To suppress it again after re-review" in alert.body


def test_expired_held_only_is_urgent() -> None:
    alert = format_suppression_expired_alert(
        [(_sup(), [_p("api", Impact.HELD, "strict")])], project=None)
    assert alert.priority == 1
    assert alert.title.endswith("— 1 project quarantine held by the breaker")


def test_expired_project_with_nothing_found() -> None:
    alert = format_suppression_expired_alert(
        [(_sup(scope="project"), [_p("wiki", Impact.NO_FINDING)])], project="wiki")
    assert alert.priority == 0
    assert alert.title == "[boxmunge:wiki] CVE-2026-57433 project suppression expired — no effect"
