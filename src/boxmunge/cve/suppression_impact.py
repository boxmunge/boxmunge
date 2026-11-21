# SPDX-License-Identifier: Apache-2.0
"""What a suppression's expiry does to a project: foreseen, or as it happened.

A suppression nearing its ``until`` date is warned about in advance
(``WARN_BEFORE``), and its expiry is alerted. Both alerts say, per project,
what the expiry means, so an operator knows whether to act now.

Pure: decisions in, ``ProjectImpact`` out. The policy is never restated
here. A foreseen impact classifies the decisions the scan made with the
suppression list as it will be on the suppression's ``until`` date
(``suppressions_at_expiry``, re-judged by the real policy in
``commands.security_scan_evaluate``); an actual one classifies the scan's
own decisions plus what the fleet run's enforcement did.

Timing: ``Suppression.is_active`` compares ``until`` with the scan's
``today``, a UTC date, so a suppression stops applying at 00:00 UTC on
``until`` (``expires_at``). A fleet run takes one clock for every project
it scans. The window is measured in hours from that clock, not in UTC
dates: the nightly timer fires once a day at a local time, and the time
between two runs' clocks is 24 hours give or take the timer's 30-minute
jitter, an hour's DST shift and up to an hour waiting on a KEV watch tick,
so at most ``MAX_RUN_GAP``. The first run whose clock is within
``WARN_BEFORE`` of the expiry is then at least ``WARN_BEFORE - MAX_RUN_GAP``
(24 hours) ahead, provided the previous night's run happened. If it was
missed, the next run in the window still warns, with less notice.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from enum import Enum

from boxmunge.cve.policy import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.suppressions import Suppression

MAX_RUN_GAP = timedelta(hours=28)
WARN_BEFORE = timedelta(hours=24) + MAX_RUN_GAP


def expires_at(sup: Suppression) -> datetime:
    """When the suppression stops applying: 00:00 UTC on ``until``."""
    return datetime.combine(sup.until, time.min, tzinfo=timezone.utc)


def in_warning_window(sup: Suppression, *, today: date, now: datetime) -> bool:
    """Still applies today, and stops applying within WARN_BEFORE of ``now``."""
    return sup.is_active(today=today) and expires_at(sup) - now <= WARN_BEFORE


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
    SCAN_FAILED = "scan_failed"   # not judged: its scan failed or was skipped
    ALERT = "alert"               # a finding below the quarantine gate: alerted, runs
    ALREADY_QUARANTINED = "already_quarantined"   # down for another finding
    NOT_APPLYING = "not_applying"  # the suppression already does not apply (a listing)
    SUPPRESSED = "suppressed"     # still covered by another suppression
    NO_FINDING = "no_finding"


# Impacts that raise an alert to priority 1: a site is or will be down, runs
# with a quarantine-level finding (the still_running convention), or could
# not be judged (a failed scan must not lower the priority).
URGENT = frozenset({Impact.QUARANTINED, Impact.HELD, Impact.AT_RISK, Impact.SCAN_FAILED})
# Impacts the expiry changes nothing about.
UNCHANGED = frozenset({Impact.ALREADY_QUARANTINED, Impact.NOT_APPLYING,
                       Impact.SUPPRESSED, Impact.NO_FINDING})


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


@dataclass(frozen=True)
class Expiry:
    """Suppressions a project's scan found expired since its prior scan,
    with that scan's decisions. ``failed``: the scan raised after recording
    its result (an enforcement error), so its outcome is not known."""

    project: str
    posture: str
    suppressions: tuple[Suppression, ...]
    decisions: tuple[ProjectDecision, ...]
    failed: bool = False


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


def _found(decisions: Sequence[ProjectDecision], cve_id: str) -> list[FindingDisposition]:
    return [fd for d in decisions for fd in d.findings if fd.finding.cve_id == cve_id]


def _worst(decisions: Sequence[ProjectDecision], cve_id: str) -> FindingDisposition | None:
    return max(_found(decisions, cve_id), key=lambda fd: _RANK[fd.disposition], default=None)


def _facts(fd: FindingDisposition | None) -> tuple[str, ...]:
    if fd is None:
        return ()
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
    project: str, posture: str, foreseen: Sequence[ProjectDecision],
    current: Sequence[ProjectDecision], cve_id: str,
) -> ProjectImpact:
    """What the expiry will do, from ``foreseen`` (decisions judged without
    the suppression). A CVE whose every current finding a known-exploited
    listing decided (``kev_override``: full KEV, or VulnCheck under paranoid)
    is NOT_APPLYING: that listing already overrides the suppression, so its
    expiry changes nothing. Not "no finding is SUPPRESSED": a fixable finding
    is IGNORED_FIXED with its suppression still in force (the policy checks
    the fix first), and its expiry can quarantine it.
    QUARANTINED means the policy will take the site down; the circuit
    breaker or an urgent autofix may still keep it up on the day."""
    now = _found(current, cve_id)
    if now and all(fd.kev_override for fd in now):
        return ProjectImpact(project, posture, Impact.NOT_APPLYING, _facts(_worst(current, cve_id)))
    fd = _worst(foreseen, cve_id)
    return ProjectImpact(project, posture, _classify(fd), _facts(fd))


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
    elif quarantined and fd is not None and fd.disposition in (
            Disposition.STILL_RUNNING_AT_RISK, Disposition.AWAITING_FIX,
            Disposition.INFORMATIONAL, Disposition.IGNORED_FIXED):
        impact = Impact.ALREADY_QUARANTINED
    return ProjectImpact(project, posture, impact, _facts(fd))


def not_judged(project: str, posture: str = "") -> ProjectImpact:
    """A project whose scan failed or was skipped this run."""
    return ProjectImpact(project, posture, Impact.SCAN_FAILED)
