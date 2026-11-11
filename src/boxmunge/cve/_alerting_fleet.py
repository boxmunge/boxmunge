# SPDX-License-Identifier: Apache-2.0
"""Fleet-level alert formatters: one alert per scan run, not per project.

Pure functions: in-memory values in, ``Alert`` out. Consumers import them
from ``boxmunge.cve.alerting``.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from boxmunge.cve._alerting_types import Alert
from boxmunge.cve.kev import KEV_DEFAULT_SOURCES, KevCatalog
from boxmunge.cve.suppressions import Suppression

_MAX_LINES = 20


def format_kev_stale_alert(
    kev: KevCatalog, *, stale_reason: str | None, tried: Sequence[str],
) -> Alert:
    """The CISA KEV catalog is stale/missing, or this run's refresh failed
    in a way that needs the operator (a rejected catalog, a bad config).

    ``stale_reason`` says which freshness condition fired (None if the
    cached catalog is still fresh); ``tried`` is one line per source this
    run tried, with its error or that it answered.

    Priority 1 because a degraded KEV feed silently disables the only
    quarantine trigger of relaxed and balanced (the default) — the operator
    must know the exploitation-signal protection is at risk.
    """
    if stale_reason is not None:
        title = "CISA KEV feed stale — exploitation defense degraded"
        lines = ["The cached CISA Known Exploited Vulnerabilities catalog is stale "
                 "or missing.", f"Why: {stale_reason}."]
    else:
        title = "CISA KEV refresh rejected — previous catalog kept"
        lines = ["The cached CISA Known Exploited Vulnerabilities catalog is still "
                 "fresh, but it will go stale if the sources stay broken."]
    lines.append(
        f"Cached catalog: released {_iso(kev.released_at, 'unknown')}, last fetched "
        f"{_iso(kev.fetched_at, 'never fetched')}, from {kev.source or 'no source'} "
        f"({len(kev.cve_ids)} CVEs).")
    if tried:
        lines.append("Sources tried this run, in order:")
        lines += [f"- {line}" for line in tried]
    lines += [
        "",
        "KEV-based quarantine is fail-safe (sites stay up), so actively-"
        "exploited CVEs will NOT be auto-quarantined once the catalog is "
        "stale. Under posture relaxed and balanced (the default) KEV is the "
        "only quarantine trigger: until the catalog is fresh again, nothing "
        "can quarantine those projects. Check egress to the sources above "
        "(kev.sources in boxmunge.yml sets them) and the cve-scan log.",
    ]
    return Alert(kind="kev_stale", title=title, body="\n".join(lines), priority=1)


def format_kev_withdrawn_alert(source: str | None, withdrawn: Sequence[str]) -> Alert:
    """The refreshed KEV catalog no longer lists a few CVEs the cached one
    did. Accepted (CISA does withdraw the odd entry). Normal priority: a
    quarantine held for one of them is kept with its own P1, and more
    withdrawals than that are rejected with a P1 instead."""
    n = len(withdrawn)
    return Alert(
        kind="kev_withdrawn",
        title=f"CISA KEV no longer lists {n} CVE{'s' if n != 1 else ''}",
        body="\n".join([
            f"The KEV catalog from {source} no longer lists:",
            *(f"- {cve}" for cve in withdrawn),
            "",
            "They no longer count as actively exploited. A quarantine held for one "
            "of them is not lifted automatically while its images still contain it: "
            "scans and deploys keep it, a priority-1 alert names the project, and "
            "`boxmunge security resume <project>` accepts the withdrawal. Check "
            "CISA's KEV page if this is unexpected.",
        ]),
        priority=0,
    )


def format_kev_sources_disagree_alert(
    source: str | None, lines: Sequence[str], *, overridden: Sequence[str] = (),
) -> Alert:
    """An earlier source in kev.sources served an older catalog lacking CVEs
    the cached one lists, and a later source's catalog was cached instead
    (kev_refresh, CVE-03). Normal priority while that is a source catching
    up; priority 1 once it has ``overridden`` the first source (or CISA's
    feed) on repeated runs or against an old cache: then the later source,
    not the operator's first choice, decides what counts as exploited."""
    cisa = KEV_DEFAULT_SOURCES[0]
    if overridden:
        title = f"CISA KEV first source overridden by {source}"
    else:
        title = "CISA KEV sources disagree — newer catalog kept"
    if cisa in overridden or any(line.startswith(f"{cisa}:") for line in lines):
        advice = (f"CISA's own feed is the source passed over, so check what {source} "
                  f"serves: a copy of CISA's catalog does not list CVEs CISA does not.")
    else:
        advice = ("If the earlier source is a mirror you run, check that it syncs; if this "
                  f"repeats once it has caught up, check what {source} serves.")
    lead = (f"{', '.join(overridden)} has been passed over for {source} on more than one "
            f"run since it last served a catalog that was used (or against an old cache):"
            if overridden else
            "A source ranked earlier in kev.sources served an older KEV catalog that "
            "lacks CVEs the cached one lists:")
    return Alert(
        kind="kev_sources_disagree",
        title=title,
        body="\n".join([
            lead,
            *(f"- {line}" for line in lines),
            "",
            f"The catalog from {source} was cached instead, so those CVEs still count as "
            f"actively exploited. {advice}",
        ]),
        priority=1 if overridden else 0,
    )


def _iso(value: datetime | None, missing: str) -> str:
    return value.isoformat() if value else missing


def format_scan_failure_alert(problems: dict[str, list[str]]) -> Alert:
    """One alert per run naming every project that was not fully scanned.

    ``problems`` maps project → human lines (an error, or each image or
    service that was not covered). Priority 1: an unscanned image is not
    protected by CVE quarantine, and a failed quarantine action may leave a
    site serving traffic.
    """
    n = len(problems)
    title = (
        f"CVE scan incomplete — {n} project"
        f"{'s' if n != 1 else ''} not fully scanned"
    )
    lines: list[str] = []
    for project in sorted(problems):
        for reason in problems[project]:
            lines.append(f"- {project}: {reason}")
    if len(lines) > _MAX_LINES:
        extra = len(lines) - _MAX_LINES
        lines = lines[:_MAX_LINES] + [f"... and {extra} more (see the cve-scan log)"]
    lines += [
        "",
        "Images that were not scanned are not covered by CVE quarantine until "
        "a scan succeeds. Inspect with `boxmunge log --component cve-scan` and "
        "re-run `boxmunge security scan`.",
    ]
    return Alert(kind="scan_failed", title=title, body="\n".join(lines), priority=1)


def format_scan_unrecorded_alert(
    problems: Mapping[str, str], last_recorded: Mapping[str, str | None],
    unreadable: Mapping[str, str],
) -> Alert:
    """Projects whose scan ran and was acted on, but whose result could not
    be written.

    ``problems`` maps project -> the error (it names the remedy);
    ``last_recorded`` maps it to when its last recorded result was made, or
    None; ``unreadable`` maps those whose recorded result cannot be read to
    why. The run's quarantines and alerts happened; what is lost is the
    record, so the project's view and freshness check show the older result
    until a write succeeds. Priority 1: a scan that cannot be recorded
    keeps failing, and the freshness check will report it stale.
    """
    n = len(problems)
    title = f"CVE scan result not recorded — {n} project{'s' if n != 1 else ''}"
    lines = [f"- {project}: {problems[project]}" for project in sorted(problems)]
    lines.append("")
    lines.append("This run's scan was completed and acted on (quarantines, alerts), "
                 "but its result was not recorded.")
    for project in sorted(problems):
        when = last_recorded.get(project)
        if project in unreadable:
            lines.append(f"- {project}: the recorded result is unreadable "
                         f"({unreadable[project]}); the scan overwrites it once it can be written")
            continue
        lines.append(f"- {project}: " + (f"the last recorded result (at {when}) is still "
                     f"what `security {project}` shows" if when else "no result is "
                     "recorded, so it shows as never scanned"))
    return Alert(kind="scan_unrecorded", title=title, body="\n".join(lines), priority=1)


def format_breaker_held_alert(
    held: Mapping[str, frozenset[str]], *, threshold: int, scanned: int,
) -> Alert:
    """The circuit breaker held new quarantines instead of applying them.

    Priority 1: the held projects are running with quarantine-level
    findings until the operator decides.
    """
    n = len(held)
    per_cve: dict[str, list[str]] = {}
    for project, cves in held.items():
        for cve in cves:
            per_cve.setdefault(cve, []).append(project)
    lines = [
        f"{n} project{'s' if n != 1 else ''} would be newly quarantined in one scan "
        f"(the breaker trips at {threshold} of {scanned} scanned). That pattern "
        f"usually means a shared base-image CVE or a Trivy DB change, so the "
        f"quarantines are HELD and the projects are still running.",
        "",
        "Held, by CVE:",
    ]
    for cve in sorted(per_cve, key=lambda c: (-len(per_cve[c]), c))[:_MAX_LINES]:
        lines.append(f"- {cve}: {', '.join(sorted(per_cve[cve]))}")
    lines += [
        "",
        "Review: boxmunge security <project>",
        "Apply the held quarantines (operator only):",
        "  boxmunge security scan --apply-held",
        "Or, after review, suppress the CVE for every project (operator only):",
        "  boxmunge security suppress <CVE> --host --until <date> --reason <text>",
        "KEV-listed CVEs are never held.",
    ]
    return Alert(
        kind="breaker_held",
        title=f"Circuit breaker held {n} quarantine{'s' if n != 1 else ''}",
        body="\n".join(lines), priority=1,
    )


def format_host_suppression_expired_alert(suppressions: Sequence[Suppression]) -> Alert:
    """Host-scope suppressions that expired: once per fleet run, not once
    per project per image (audit B-14). Priority 1."""
    sups = sorted(suppressions, key=lambda s: s.cve_id)
    more = f" (+{len(sups) - 1} more)" if len(sups) > 1 else ""
    title = f"Host suppression expired — {sups[0].cve_id}{more}"
    lines = ["Host-scope suppressions (they applied to every project) expired:"]
    for s in sups:
        lines.append(f"- {s.cve_id}: added {s.added.isoformat()}, "
                     f"expired {s.until.isoformat()}")
    lines += [
        "",
        "These are active findings again on every project that has them.",
        "To re-review and extend (operator only, not from the deploy shell):",
        "  boxmunge security suppress <CVE> --host --until <date> --reason <text>",
    ]
    return Alert(kind="suppression_expired", title=title, body="\n".join(lines), priority=1)

