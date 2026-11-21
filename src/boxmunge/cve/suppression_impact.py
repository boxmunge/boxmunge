# SPDX-License-Identifier: Apache-2.0
"""What a suppression's expiry does to a project: foreseen, or as it happened.

A suppression nearing its ``until`` date is warned about in advance
(``WARN_DAYS``), and its expiry is alerted. Both alerts say, per project,
what the expiry means, so an operator knows whether to act now.

Pure: decisions in, ``ProjectImpact`` out. The policy is never restated
here. A foreseen impact classifies the decisions the scan made with the
suppression list as it will be on the suppression's ``until`` date
(``suppressions_at_expiry``, re-judged by the real policy in
``commands.security_scan_evaluate``); an actual one classifies the scan's
own decisions plus what the fleet run's enforcement did.

Timing: ``Suppression.is_active`` compares ``until`` with the scan's
``today``, a UTC date, so a suppression stops applying at 00:00 UTC on
``until``. The nightly scan runs once a day at a local time; whatever the
box's time zone, it runs once on each UTC date. The scan on UTC date
``until - 2`` is therefore between 24 and 48 hours before the expiry, and
it is the first scan in the window. If that scan is missed, the next scan
in the window (``until - 1``) still warns, with less notice.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum

from boxmunge.cve.policy import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.suppressions import Suppression

# Warn on a scan whose UTC date is at most this many days before ``until``.
WARN_DAYS = 2


def in_warning_window(sup: Suppression, today: date) -> bool:
    """Still applies today, and stops applying within WARN_DAYS."""
    return sup.is_active(today=today) and sup.until - today <= timedelta(days=WARN_DAYS)


def suppressions_at_expiry(
    suppressions: Sequence[Suppression], until: date,
) -> tuple[Suppression, ...]:
    """The suppressions that still apply on ``until``: the list a scan on
    the expiry day would judge with (any other suppression expiring by then
    is gone too)."""
    return tuple(s for s in suppressions if s.is_active(today=until))


class Impact(Enum):
    """One project's outcome for one CVE, worst first."""

    QUARANTINED = "quarantined"
    HELD = "held"                 # quarantine-level, held by the circuit breaker
    AT_RISK = "at_risk"           # quarantine-level, still running
    ALERT = "alert"               # a finding below the quarantine gate: alerted, runs
    SUPPRESSED = "suppressed"     # still covered by another suppression
    NO_FINDING = "no_finding"


# Impacts that raise an alert to priority 1: a site is or will be down, or
# runs with a quarantine-level finding (the still_running convention).
URGENT = frozenset({Impact.QUARANTINED, Impact.HELD, Impact.AT_RISK})


@dataclass(frozen=True)
class ProjectImpact:
    project: str
    posture: str
    impact: Impact
    # The finding's deciding facts: "known exploited (CISA KEV)", "fix available".
    facts: tuple[str, ...] = ()


@dataclass(frozen=True)
class Foreseen:
    """A suppression in its warning window and what its expiry will do to
    the project whose scan judged it."""

    suppression: Suppression
    impact: ProjectImpact


# The finding that decides a project's outcome when several packages or
# images carry the CVE.
_RANK = {
    Disposition.QUARANTINE: 5,
    Disposition.STILL_RUNNING_AT_RISK: 4,
    Disposition.AWAITING_FIX: 3,
    Disposition.INFORMATIONAL: 2,
    Disposition.IGNORED_FIXED: 1,
    Disposition.SUPPRESSED: 0,
}


def _worst(decisions: Sequence[ProjectDecision], cve_id: str) -> FindingDisposition | None:
    found = [fd for d in decisions for fd in d.findings if fd.finding.cve_id == cve_id]
    return max(found, key=lambda fd: _RANK[fd.disposition], default=None)


def _facts(fd: FindingDisposition) -> tuple[str, ...]:
    facts = []
    if fd.exploited_by:
        facts.append(f"known exploited ({fd.exploited_label})")
    if fd.finding.fix_available:
        facts.append("fix available")
    return tuple(facts)


def _classify(fd: FindingDisposition | None) -> Impact:
    if fd is None:
        return Impact.NO_FINDING
    return {
        Disposition.QUARANTINE: Impact.QUARANTINED,
        Disposition.STILL_RUNNING_AT_RISK: Impact.AT_RISK,
        Disposition.SUPPRESSED: Impact.SUPPRESSED,
    }.get(fd.disposition, Impact.ALERT)


def foreseen_impact(
    project: str, posture: str, decisions: Sequence[ProjectDecision], cve_id: str,
) -> ProjectImpact:
    """What the expiry will do, from decisions judged without the suppression.
    QUARANTINED here means the policy will take the site down; the circuit
    breaker or an urgent autofix may still keep it up on the day."""
    fd = _worst(decisions, cve_id)
    return ProjectImpact(project, posture, _classify(fd), _facts(fd) if fd else ())


def actual_impact(
    project: str, posture: str, decisions: Sequence[ProjectDecision], cve_id: str,
    *, quarantined: bool, held: frozenset[str],
) -> ProjectImpact:
    """What the expiry did in this run: the scan's decisions, after the
    fleet's enforcement. ``held`` is the CVEs the breaker held for this
    project; ``quarantined`` whether the project is quarantined now."""
    fd = _worst(decisions, cve_id)
    impact = _classify(fd)
    if impact is Impact.QUARANTINED and not quarantined:
        impact = Impact.HELD if cve_id in held else Impact.AT_RISK
    return ProjectImpact(project, posture, impact, _facts(fd) if fd else ())
