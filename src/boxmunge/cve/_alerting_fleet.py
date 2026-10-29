# SPDX-License-Identifier: Apache-2.0
"""Fleet-level alert formatters: one alert per scan run, not per project.

Pure functions: in-memory values in, ``Alert`` out. Consumers import them
from ``boxmunge.cve.alerting``.
"""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone

from boxmunge.cve._alerting_types import Alert
from boxmunge.cve.policy import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.suppressions import Suppression

_MAX_LINES = 20


def format_kev_stale_alert(
    fetched_at: datetime | None, *, stale: bool = True, rejected: str | None = None,
) -> Alert:
    """The CISA KEV catalog is stale/missing, or this run's refresh was
    rejected by the sanity floor.

    Priority 1 because a degraded KEV feed silently disables the lowest
    tier's only quarantine trigger — the operator must know the
    exploitation-signal protection is at risk.
    """
    when = fetched_at.isoformat() if fetched_at else "never fetched"
    if stale:
        title = "CISA KEV feed stale — exploitation defense degraded"
        state = "The cached CISA Known Exploited Vulnerabilities catalog is stale or missing."
    else:
        title = "CISA KEV refresh rejected — previous catalog kept"
        state = (
            "The cached CISA Known Exploited Vulnerabilities catalog is still "
            "fresh, but it will go stale if the feed stays broken."
        )
    lines = [state, f"Last good fetch: {when}"]
    if rejected:
        lines.append(f"This run's refresh was rejected: {rejected}.")
    lines += [
        "",
        "KEV-based quarantine is fail-safe (sites stay up), so actively-"
        "exploited CVEs will NOT be auto-quarantined once the catalog is "
        "stale. Check egress to cisa.gov and the cve-scan log.",
    ]
    return Alert(kind="kev_stale", title=title, body="\n".join(lines), priority=1)


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
) -> Alert:
    """Projects whose scan ran and was acted on, but whose result could not
    be written.

    ``problems`` maps project -> the error (it names the remedy);
    ``last_recorded`` maps it to when its last recorded result was made, or
    None. The run's quarantines and alerts happened; what is lost is the
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
        lines.append(f"- {project}: " + (f"the last recorded result (at {when}) is still "
                     f"what `security {project}` shows" if when else "no result is "
                     f"recorded, so it shows as never scanned"))
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


# ---------- grace heads-up helpers ----------


def _quarantine_findings(
    decision: ProjectDecision,
) -> tuple[FindingDisposition, ...]:
    return tuple(
        d for d in decision.findings if d.disposition == Disposition.QUARANTINE
    )


def _at_risk_findings(
    decision: ProjectDecision,
) -> tuple[FindingDisposition, ...]:
    return tuple(
        d for d in decision.findings
        if d.disposition == Disposition.STILL_RUNNING_AT_RISK
    )


def _format_finding_summary(fd: FindingDisposition) -> str:
    """Compact 'CVE-... (Severity, ...)' clause used in heads-up bullets.

    Mirrors the explanation prefix used elsewhere so the operator sees
    consistent severity wording across alert kinds.
    """
    cve = fd.finding.cve_id
    base = fd.base_severity.value
    eff = fd.effective_severity.value
    if base != eff and fd.hardening_penalty > 0:
        return (
            f"{cve} ({base} → effective {eff} via hardening penalty, "
            f"no upstream fix)"
        )
    return f"{cve} ({eff}, no upstream fix)"


def format_grace_heads_up_alert(
    *,
    expires_at: datetime,
    decisions_by_project: dict[str, ProjectDecision],
    posture_by_project: dict[str, str],
    dangerously_by_project: dict[str, bool],
) -> Alert:
    """One-time fleet-level "heads-up" alert for the migration grace window.

    Lists projects that *would* quarantine at grace expiry and projects
    running with ``dangerously_disable_quarantine`` that hit a finding
    over their posture threshold. Includes posture pointers and the
    suppression command syntax so the operator can configure before
    enforcement bites.

    Empty sections are omitted entirely (no "none." line).
    """
    # Compute "hours remaining" relative to "now" — clamped >=1 so the
    # title always reads sensibly even if the window is on the edge.
    now = datetime.now(timezone.utc)
    delta = expires_at - now
    hours_remaining = max(1, math.ceil(delta.total_seconds() / 3600))
    title = (
        f"CVE policy enforcement begins in {hours_remaining}h"
    )

    # Bucket projects.
    #
    # Audit F-7: the at-risk-running section is populated by intersecting
    # `dangerously_by_project` (the operator-declared exemption) with the
    # set of projects that have would-quarantine findings. A project with
    # the dangerously flag set but no findings over its posture threshold
    # is NOT at-risk-running and must not be listed; conversely, a project
    # without the flag whose findings are STILL_RUNNING_AT_RISK has no
    # way to land that disposition without the flag — so the two
    # signals are equivalent in practice today, but we read the explicit
    # dict so the alert body matches the source-of-truth signal the
    # caller supplies (rather than a derived view of it).
    would_quarantine: list[tuple[str, FindingDisposition]] = []
    at_risk: list[tuple[str, FindingDisposition]] = []
    other_projects: list[str] = []
    for name in sorted(decisions_by_project.keys()):
        decision = decisions_by_project[name]
        q_findings = _quarantine_findings(decision)
        r_findings = _at_risk_findings(decision)
        if q_findings:
            # One representative finding per project — most-severe first
            # is already the convention from policy.evaluate_project.
            would_quarantine.append((name, q_findings[0]))
        elif r_findings and dangerously_by_project.get(name) is True:
            at_risk.append((name, r_findings[0]))
        else:
            other_projects.append(name)

    n_projects = len(decisions_by_project)
    n_quar = len(would_quarantine)
    n_risk = len(at_risk)
    n_other = len(other_projects)

    expires_display = expires_at.astimezone(timezone.utc).strftime(
        "%Y-%m-%d %H:%M",
    )

    lines: list[str] = []
    lines.append(
        "boxmunge v0.6.0 introduces CVE policy. After a 24-hour grace "
        "window, projects",
    )
    lines.append(
        "with unpatched high-severity CVEs will be quarantined "
        "automatically.",
    )
    lines.append("")
    lines.append(f"First scan results across {n_projects} projects:")
    lines.append("")

    # Would-quarantine section.
    if would_quarantine:
        lines.append(
            f"Would quarantine after grace ends ({n_quar} projects):",
        )
        # Align project names for readability — width ~12 unless longer.
        name_width = max(len(name) for name, _ in would_quarantine)
        for name, fd in would_quarantine:
            posture = posture_by_project.get(name, "balanced")
            summary = _format_finding_summary(fd)
            lines.append(
                f"  - {name:<{name_width}}  {summary} — posture: {posture}",
            )
    else:
        lines.append(
            "Would quarantine after grace ends: No projects would be "
            "quarantined.",
        )
    lines.append("")

    # At-risk-running section. Audit F-7: omit entirely when empty
    # (matches the "don't show empty bullet lists" pattern; the prior
    # "none." line was an exception that the audit flagged for cleanup).
    if at_risk:
        lines.append(
            f"At-risk-running (dangerously_disable_quarantine={n_risk} "
            f"projects):",
        )
        name_width = max(len(name) for name, _ in at_risk)
        for name, fd in at_risk:
            summary = _format_finding_summary(fd)
            lines.append(f"  - {name:<{name_width}}  {summary}")
        lines.append("")

    lines.append(f"Other projects ({n_other}): clean or sub-threshold findings only.")
    lines.append("")
    lines.append("Configure per-project posture in manifest.yml:")
    lines.append("  security:")
    lines.append("    posture: relaxed | balanced (default) | strict | paranoid")
    lines.append("")
    lines.append("Suppress a specific CVE (with operator review):")
    lines.append(
        "  boxmunge security suppress <CVE> --project <name> \\",
    )
    lines.append("      --until <date> --reason <text>")
    lines.append("")
    lines.append(f"Enforcement begins: {expires_display} UTC")

    body = "\n".join(lines)
    return Alert(
        kind="grace_heads_up", title=title, body=body, priority=1,
    )
