# SPDX-License-Identifier: Apache-2.0
"""Suppression expiry alerts: the advance warning and the expiry itself.

Each names, per affected project, what the expiry will do or did
(cve.suppression_impact), grouped by outcome with the worst in the title,
and the commands to act on it. Host scope is one alert per fleet run
(audit B-14); project scope one per project per kind.

Pure functions: in-memory values in, ``Alert`` out. Consumers import them
from ``boxmunge.cve.alerting``.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from boxmunge.cve._alerting_types import Alert
from boxmunge.cve.suppression_impact import (
    UNCHANGED, URGENT, Impact, ProjectImpact, expires_at,
)
from boxmunge.cve.suppressions import Suppression

# One suppression and its outcome on each project that judged it.
Entry = tuple[Suppression, Sequence[ProjectImpact]]

_MAX_NAMED = 10

# Impact → (one project, several projects) for the warning and the expiry.
_WILL = {
    Impact.QUARANTINED: ("will be quarantined (stopped)", "will be quarantined (stopped)"),
    Impact.HELD: ("will be held by the circuit breaker", "will be held by the circuit breaker"),
    Impact.AT_RISK: ("will keep running at quarantine level (quarantine disabled by config)",
                     "will keep running at quarantine level (quarantine disabled by config)"),
    Impact.SCAN_FAILED: ("was not judged (its scan failed or was skipped)",
                         "were not judged (their scans failed or were skipped)"),
    Impact.ALERT: ("will alert only and keep running", "will alert only and keep running"),
    Impact.ALREADY_QUARANTINED: ("is already quarantined for another finding",
                                 "are already quarantined for another finding"),
    Impact.NOT_APPLYING: ("already ignores it (a known-exploited listing overrides it)",
                          "already ignore it (a known-exploited listing overrides it)"),
    Impact.SUPPRESSED: ("stays covered by another suppression",
                        "stay covered by another suppression"),
}
_DID = {
    Impact.QUARANTINED: ("is quarantined (stopped)", "are quarantined (stopped)"),
    Impact.HELD: ("is held by the circuit breaker, still running",
                  "are held by the circuit breaker, still running"),
    Impact.AT_RISK: ("is at quarantine level but still running",
                     "are at quarantine level but still running"),
    Impact.SCAN_FAILED: ("was not judged: its scan failed or was skipped",
                         "were not judged: their scans failed or were skipped"),
    Impact.ALERT: ("alerts only and keeps running", "alert only and keep running"),
    Impact.ALREADY_QUARANTINED: ("is already quarantined for another finding",
                                 "are already quarantined for another finding"),
    Impact.NOT_APPLYING: ("was already ignoring it (a known-exploited listing overrode it)",
                          "were already ignoring it (a known-exploited listing overrode it)"),
    Impact.SUPPRESSED: ("is still covered by another suppression",
                        "are still covered by another suppression"),
}
# The title's worst outcome, for N projects.
_HEADLINE_WILL = {
    Impact.QUARANTINED: "will be quarantined", Impact.HELD: "will be held",
    Impact.AT_RISK: "will run at risk", Impact.SCAN_FAILED: "not judged (scan failed)",
    Impact.ALERT: "will alert only",
}
_HEADLINE_DID = {
    Impact.QUARANTINED: "quarantined", Impact.HELD: "quarantine held by the breaker",
    Impact.AT_RISK: "running at risk", Impact.SCAN_FAILED: "not judged (scan failed)",
    Impact.ALERT: "alerting only",
}
_ORDER = tuple(Impact)  # worst first


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' if n != 1 else ''}"


def _named(impacts: Sequence[ProjectImpact], *, with_posture: bool) -> str:
    def one(i: ProjectImpact) -> str:
        tags = ([i.posture] if with_posture else []) + list(i.facts)
        return f"{i.project} [{'; '.join(tags)}]" if tags else i.project
    names = [one(i) for i in sorted(impacts, key=lambda i: i.project)]
    more = f" (+{len(names) - _MAX_NAMED} more)" if len(names) > _MAX_NAMED else ""
    return ", ".join(names[:_MAX_NAMED]) + more


def _impact_lines(impacts: Sequence[ProjectImpact], *, foreseen: bool,
                  host: bool) -> list[str]:
    phrases = _WILL if foreseen else _DID
    lines = []
    for impact in _ORDER[:-1]:
        group = [i for i in impacts if i.impact is impact]
        if not group:
            continue
        one, many = phrases[impact]
        if host:
            count = _plural(len(group), "project")
            verb = one if len(group) == 1 else many
            lines.append(f"- {count} {verb}: {_named(group, with_posture=True)}")
        else:
            lines.append(f"- {_named(group, with_posture=True)} {one}")
    none = sum(i.impact is Impact.NO_FINDING for i in impacts)
    if none:
        lines.append(f"- {_plural(none, 'project')} {'have' if none != 1 else 'has'} "
                     f"no finding for it (no effect)" if host
                     else "- no finding for it in the project's images (no effect)")
    return lines


def _worst(entries: Sequence[Entry]) -> tuple[Impact | None, int]:
    """The worst outcome that changes anything, and how many projects it hits."""
    by_project: dict[str, Impact] = {}
    for _, impacts in entries:
        for i in impacts:
            held = by_project.get(i.project)
            if held is None or _ORDER.index(i.impact) < _ORDER.index(held):
                by_project[i.project] = i.impact
    for impact in _ORDER:
        if impact in UNCHANGED:
            break
        n = sum(v is impact for v in by_project.values())
        if n:
            return impact, n
    return None, 0


def _headline(entries: Sequence[Entry], *, foreseen: bool, host: bool) -> str:
    impact, n = _worst(entries)
    if impact is None:
        return "no project affected" if host else "no effect"
    phrase = (_HEADLINE_WILL if foreseen else _HEADLINE_DID)[impact]
    return f"{_plural(n, 'project')} {phrase}" if host else phrase


def _priority(entries: Sequence[Entry]) -> int:
    urgent = any(i.impact in URGENT for _, impacts in entries for i in impacts)
    return 1 if urgent else 0


def _subject(entries: Sequence[Entry], scope: str) -> str:
    sups = [s for s, _ in entries]
    more = f" (+{len(sups) - 1} more)" if len(sups) > 1 else ""
    return f"{sups[0].cve_id}{more} {scope} suppression{'s' if len(sups) > 1 else ''}"


def _hours_left(sup: Suppression, now: datetime) -> str:
    hours = int((expires_at(sup) - now).total_seconds() // 3600)
    return "in under an hour" if hours < 1 else f"in {hours}h"


def _extend(cve: str, flag: str) -> list[str]:
    return [f"  boxmunge security unsuppress {cve} {flag}",
            f"  boxmunge security suppress {cve} {flag} --until <date> --reason <text>"]


def _actions(entries: Sequence[Entry], project: str | None, *, foreseen: bool) -> list[str]:
    flag = "--host" if project is None else f"--project {project}"
    who = ("operator only, not from the deploy shell" if project is None
           else "the deploy shell can do this")
    lead = "To keep it suppressed, re-review and extend" if foreseen else \
        "To suppress it again after re-review"
    cves = sorted({s.cve_id for s, _ in entries})
    lines = ["", f"{lead} ({who}):"]
    for cve in cves:
        lines += _extend(cve, flag)
    review = project or "<project>"
    lines.append(f"Review: boxmunge security {review}")
    return lines


def _sorted(entries: Sequence[Entry]) -> list[Entry]:
    return sorted(entries, key=lambda e: (e[0].until, e[0].cve_id))


def format_suppression_expiring_alert(
    entries: Sequence[Entry], *, project: str | None, now: datetime,
) -> Alert:
    """Suppressions that stop applying within the warning window, and what
    that will do. ``project`` None is host scope: every project of a full
    fleet run, those it could not scan as SCAN_FAILED. Sent once per (CVE,
    scope, until). Priority 1 when a project will be quarantined, run at
    risk or was not judged, else normal."""
    entries = _sorted(entries)
    host = project is None
    scope = "host" if host else "project"
    first = entries[0][0]
    title = (f"{_subject(entries, scope)} expire{'s' if len(entries) == 1 else ''} "
             f"{_hours_left(first, now)} — {_headline(entries, foreseen=True, host=host)}")
    if not host:
        title = f"[boxmunge:{project}] {title}"
    lines = [] if host else [f"Project: {project}"]
    for sup, impacts in entries:
        lines += [
            f"{sup.cve_id}: the {scope} suppression stops applying "
            f"{sup.until.isoformat()} 00:00 UTC ({_hours_left(sup, now)}). Then:",
            *_impact_lines(impacts, foreseen=True, host=host),
        ]
    lines += _actions(entries, project, foreseen=True)
    lines += ["", *(f"{s.cve_id} was added {s.added.isoformat()} by {s.reviewed_by}: "
                    f"{s.reason}" for s, _ in entries),
              "Predicted from this scan's findings and each project's posture; the "
              "circuit breaker or an urgent autofix can still keep a site up."]
    return Alert(kind="suppression_expiring", title=title, body="\n".join(lines),
                 priority=_priority(entries))


def format_suppression_expired_alert(
    entries: Sequence[Entry], *, project: str | None, partial: bool = False,
    no_full_run_since: datetime | None = None,
) -> Alert:
    """Suppressions that stopped applying since the prior scan, and what this
    run did about each: quarantined, held by the circuit breaker, running at
    risk, alerting, or nothing to do. Host scope (``project`` None) is once
    per full fleet run (audit B-14). ``partial``: a host alert from a run
    that judged only some projects (the notice record was unusable, so it
    could not be left to the fleet run); it says so and is priority 1, since
    the rest of the fleet is unknown. ``no_full_run_since``: a partial alert
    for a host expiry left pending that long ago, because no full nightly
    run has completed since. Otherwise priority 1 when a project was
    quarantined, held, left at risk or not judged, else normal."""
    entries = _sorted(entries)
    host = project is None
    scope = "host" if host else "project"
    title = (f"{_subject(entries, scope)} expired — "
             f"{_headline(entries, foreseen=False, host=host)}")
    if not host:
        title = f"[boxmunge:{project}] {title}"
    lines = [] if host else [f"Project: {project}"]
    for sup, impacts in entries:
        lines += [
            f"{sup.cve_id}: the {scope} suppression added {sup.added.isoformat()} "
            f"expired {sup.until.isoformat()} and no longer applies. This scan:",
            *_impact_lines(impacts, foreseen=False, host=host),
        ]
    if partial:
        title += " (partial: one scan's projects)"
        lines.append("This run judged only the projects above; the rest of the fleet was "
                     "not scanned. The nightly scan judges them.")
        if no_full_run_since is not None:
            lines.append(f"No full nightly scan has completed since this expiry was found "
                         f"({no_full_run_since.isoformat(timespec='minutes')}): check "
                         f"boxmunge-maintenance.timer and the cve-scan log.")
    lines += _actions(entries, project, foreseen=False)
    return Alert(kind="suppression_expired", title=title, body="\n".join(lines),
                 priority=1 if partial else _priority(entries))


def format_suppression_record_alert(path: str, error: str, remedy: str) -> Alert:
    """The suppression notice record cannot be used: no expiry warning is
    sent until it can (and none is recorded, so none repeats every scan).
    Sent by the full fleet run only, so at most once a night. Priority 1:
    suppressions can now expire without notice."""
    return Alert(
        kind="suppression_record",
        title="Suppression expiry warnings stopped — notice record unusable",
        body="\n".join([
            f"The suppression notice record {path} cannot be used:",
            f"  {error}",
            "",
            "Until it can, no suppression expiry warning is sent, and a host "
            "suppression expiry found by a single-project scan or KEV watch tick is "
            "alerted at once, for that run's projects only.",
            f"To fix: {remedy}.",
        ]),
        priority=1,
    )
