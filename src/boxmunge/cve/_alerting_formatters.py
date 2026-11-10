# SPDX-License-Identifier: Apache-2.0
"""Per-project alert formatters for CVE policy state transitions.

One alert per project per kind of transition, never one per finding
(audit B-14): a project's first scan, or an image rebuild, can surface
dozens of findings at once, and a storm of pushes trains operators to
ignore the channel that carries quarantine alerts.

Pure functions: take in-memory values, return ``Alert`` instances. No I/O,
no logging. Fleet-level formatters (KEV, scan failure)
live in ``_alerting_fleet``; consumers import from ``boxmunge.cve.alerting``.
"""

from __future__ import annotations

from collections.abc import Sequence

from boxmunge.cve._alerting_types import Alert, Hit
from boxmunge.cve.policy import Disposition, FindingDisposition
from boxmunge.cve.policy_types import BALANCED_KEV_ONLY_SINCE
from boxmunge.cve.suppressions import Suppression

# Lines listed in an aggregated alert body before "... and N more".
_MAX_LISTED = 10
# Findings named in the informational digest.
_DIGEST_TOP = 5

def _ordered(hits: Sequence[Hit]) -> list[Hit]:
    """Most severe first, then by CVE id, for stable titles and bodies."""
    return sorted(hits, key=lambda h: (-h.disposition.effective_severity.rank,
                                       h.disposition.finding.cve_id,
                                       h.disposition.finding.package))


def _sev(fd: FindingDisposition) -> str:
    base, eff = fd.base_severity.value, fd.effective_severity.value
    if fd.hardening_penalty > 0 and base != eff:
        return f"{base} → effective {eff} via penalty +{fd.hardening_penalty}"
    return eff


def _line(hit: Hit) -> str:
    fd = hit.disposition
    kev = ", CISA KEV" if fd.kev_listed else ""
    return (f"- {fd.finding.cve_id} ({_sev(fd)}{kev}) in "
            f"{fd.finding.package or '?'} — {hit.image_ref}")


def _listing(hits: Sequence[Hit], limit: int = _MAX_LISTED) -> list[str]:
    lines = [_line(h) for h in hits[:limit]]
    if len(hits) > limit:
        lines.append(f"... and {len(hits) - limit} more")
    return lines


def _more(n: int) -> str:
    return f" (+{n} more)" if n else ""


def _cve_count(hits: Sequence[Hit]) -> int:
    return len({h.disposition.finding.cve_id for h in hits})


def format_quarantine_alert(project: str, hits: Sequence[Hit]) -> Alert:
    """The project was quarantined. Priority 1. Names the worst finding."""
    hits = _ordered(hits)
    head = hits[0].disposition
    cve = head.finding.cve_id
    why = ("actively exploited — CISA KEV" if head.kev_listed
           else head.effective_severity.value)
    title = (f"[boxmunge:{project}] QUARANTINED — {cve} ({why})"
             f"{_more(_cve_count(hits) - 1)}")
    body = "\n".join([
        f"Project: {project}",
        "Quarantine-level findings:",
        *_listing(hits),
        "",
        head.explanation,
        "",
        "Service stopped, maintenance page active.",
        "",
        "To recover: deploy a fixed release (its images are scanned first; the",
        "quarantine lifts once it is live), or once the CVE is fixed upstream or",
        f"suppressed: boxmunge security resume {project}",
    ])
    return Alert(kind="quarantine", title=title, body=body, priority=1)


def format_still_running_alert(project: str, hits: Sequence[Hit]) -> Alert:
    """Quarantine-level findings on a project that opted out. Priority 1."""
    hits = _ordered(hits)
    head = hits[0].disposition
    title = (f"[boxmunge:{project}] [STILL RUNNING — quarantine disabled by config] "
             f"{head.finding.cve_id} ({head.effective_severity.value})"
             f"{_more(_cve_count(hits) - 1)}")
    body = "\n".join([
        f"Project: {project} — QUARANTINE DISABLED BY CONFIG",
        "Findings that would otherwise quarantine:",
        *_listing(hits),
        "",
        head.explanation,
        "",
        "Project is still running because dangerously_disable_quarantine is true.",
        "Read-only rootfs is the only remaining post-exploit defense.",
        "",
        "To remove the exemption: drop dangerously_disable_quarantine from the",
        "manifest's security: block. To suppress a reviewed CVE:",
        f"  boxmunge security suppress {head.finding.cve_id} --project {project} \\",
        "      --until <date> --reason <text>",
    ])
    return Alert(kind="still_running", title=title, body=body, priority=1)


def format_kev_fix_pending_alert(project: str, hits: Sequence[Hit]) -> Alert:
    """An actively exploited CVE with a fix the image is not running, on a
    posture that does not quarantine it (relaxed). Priority 1, every scan."""
    hits = _ordered(hits)
    head = hits[0].disposition
    title = (f"[boxmunge:{project}] ACTIVELY EXPLOITED — {head.finding.cve_id} "
             f"fix available but not running (CISA KEV){_more(_cve_count(hits) - 1)}")
    body = "\n".join([
        f"Project: {project} — still running",
        *_listing(hits),
        "",
        head.explanation,
        "",
        "Rebuild the image (pull the fixed base image or package) and",
        "redeploy. This alert repeats on every scan until the fix is running.",
    ])
    return Alert(kind="kev_fix_pending", title=title, body=body, priority=1)


def format_kev_at_risk_alert(project: str, hits: Sequence[Hit]) -> Alert:
    """An actively exploited CVE on a project that opted out of quarantine.
    Priority 1, every scan, naming the CVE and the opt-out."""
    hits = _ordered(hits)
    head = hits[0].disposition
    title = (f"[boxmunge:{project}] [STILL RUNNING — quarantine disabled by config] "
             f"ACTIVELY EXPLOITED {head.finding.cve_id} (CISA KEV)"
             f"{_more(_cve_count(hits) - 1)}")
    body = "\n".join([
        f"Project: {project} — dangerously_disable_quarantine: true",
        *_listing(hits),
        "",
        head.explanation,
        "",
        "To let boxmunge quarantine it: drop dangerously_disable_quarantine",
        "from the manifest's security: block and redeploy. This alert repeats",
        "on every scan while the finding is live.",
    ])
    return Alert(kind="kev_at_risk", title=title, body=body, priority=1)


def format_fixable_alert(project: str, hits: Sequence[Hit]) -> Alert:
    """Findings over the posture's gate whose fix the image is not running —
    including a balanced finding that was awaiting a fix when the fix lands.
    Not quarantined (the fix is the remedy), never silent. Priority 0."""
    hits = _ordered(hits)
    n = len(hits)
    title = (f"[boxmunge:{project}] {n} fixable CVE finding{'s' if n != 1 else ''} "
             f"over the posture's gate — rebuild to apply the fix")
    body = "\n".join([
        f"Project: {project}",
        "A fix exists for each of these, but the running image predates it:",
        *_listing(hits),
        "",
        "boxmunge does not rebuild images on its own. A `build:` service is",
        "rebuilt on its base image's current digest by its next stage and",
        f"promote, or prod-deploy (`prod-deploy {project} --redeploy` when",
        "nothing new was uploaded). Otherwise bump the image tag or digest (a",
        "FROM pinned by digest is never refreshed), or, for a package your",
        "Dockerfile installs, set compose `build: {no_cache: true}`, then",
        "redeploy. See CVE_POLICY.md, \"Base images and the build cache\" and",
        "\"Shipping a fix the upstream image does not have yet\".",
    ])
    return Alert(kind="fix_available", title=title, body=body, priority=0)


def format_awaiting_fix_alert(project: str, hits: Sequence[Hit]) -> Alert:
    """Findings at balanced's alert-only gate: no fix yet, not known to be
    exploited. The site stays up. Alerted once per finding; priority 0, since
    nothing needs doing tonight."""
    hits = _ordered(hits)
    n = len(hits)
    title = (f"[boxmunge:{project}] {n} CVE finding{'s' if n != 1 else ''} with no "
             f"fix yet — site stays up, nothing to do now")
    body = "\n".join([
        f"Project: {project} — still running.",
        *_listing(hits),
        "",
        hits[0].disposition.explanation,
        "",
        "You will not be alerted again for these until that changes.",
        f"Details: boxmunge security {project}",
    ])
    return Alert(kind="awaiting_fix", title=title, body=body, priority=0)


def format_hardening_upcoming_alert(project: str, hits: Sequence[Hit]) -> Alert:
    """Findings that quarantine from 0.12 but not now. Warned once per finding;
    not quarantined. Priority 0."""
    hits = _ordered(hits)
    n = len(hits)
    title = (f"[boxmunge:{project}] {n} CVE finding{'s' if n != 1 else ''} will "
             f"quarantine from 0.12 (warning only)")
    body = "\n".join([
        f"Project: {project} — still running; nothing is quarantined for this in 0.11.",
        *_listing(hits),
        "",
        hits[0].disposition.explanation,
        "",
        f"Details: boxmunge security {project}",
    ])
    return Alert(kind="hardening_upcoming", title=title, body=body, priority=0)


def format_new_findings_alert(project: str, hits: Sequence[Hit]) -> Alert:
    """Digest of findings first seen this scan that do not quarantine. Priority 0."""
    hits = _ordered(hits)
    n = len(hits)
    title = (f"[boxmunge:{project}] {n} new CVE finding{'s' if n != 1 else ''} "
             f"(informational)")
    lines = [f"Project: {project}",
             f"{n} new finding{'s' if n != 1 else ''} below the quarantine gate. "
             f"Top {min(n, _DIGEST_TOP)}:"]
    for hit in hits[:_DIGEST_TOP]:
        lines.append(_line(hit))
        lines.append(f"    {hit.disposition.explanation}")
    lines += ["", f"All findings: boxmunge security {project}"]
    return Alert(kind="informational", title=title, body="\n".join(lines), priority=0)


def format_suppression_expired_alert(
    project: str, suppressions: Sequence[Suppression],
) -> Alert:
    """Project-scope suppressions that expired between scans. Priority 1."""
    sups = sorted(suppressions, key=lambda s: s.cve_id)
    first = sups[0]
    title = (f"[boxmunge:{project}] Suppression expired — {first.cve_id}"
             f"{_more(len(sups) - 1)}")
    lines = [f"Project: {project}"]
    for s in sups:
        lines.append(f"- {s.cve_id}: added {s.added.isoformat()}, "
                     f"expired {s.until.isoformat()}")
    lines += [
        "",
        "These are active findings again; any that meet the posture threshold",
        "quarantine on this or the next scan. To re-review and extend:",
        f"  boxmunge security suppress <CVE> --project {project} \\",
        "      --until <date> --reason <text>",
    ]
    return Alert(kind="suppression_expired", title=title, body="\n".join(lines), priority=1)


def lift_reason(cve_id: str, hits: Sequence[Hit]) -> str:
    """Why the quarantine ``cve_id`` took no longer holds, from this scan's
    hits for it (any package)."""
    if not hits:
        return f"{cve_id} is no longer found in the project's images."
    fd = _ordered(hits)[0].disposition
    if fd.disposition is Disposition.AWAITING_FIX:
        return (f"The posture rules changed in boxmunge {BALANCED_KEV_ONLY_SINCE}: "
                f"balanced quarantines only on actively exploited (CISA KEV) "
                f"findings, and {cve_id} is not on the KEV catalog. {fd.explanation}")
    if fd.disposition is Disposition.SUPPRESSED:
        return f"{cve_id} is suppressed. {fd.explanation}"
    return f"{cve_id} no longer quarantines. {fd.explanation}"


def format_quarantine_lifted_alert(
    project: str, cve_id: str, reason: str, *,
    held: str | None, smoke: tuple[bool, str] | None,
) -> Alert:
    """A scan found nothing quarantine-level and lifted the quarantine.
    Sent once (the record is gone after); priority 1 only when the smoke
    test failed after the restart. ``held``: why the lift left the project
    down (quarantine_lift.start_hold)."""
    if held is not None:
        state, tail = "quarantine lifted, still down", [f"It stays down: {held}."]
    elif smoke is not None and not smoke[0]:
        state, tail = ("back up, smoke test FAILED", [f"Smoke test: {smoke[1]}"])
    else:
        state, tail = "back online", ["Smoke test: OK"]
    title = f"[boxmunge:{project}] Quarantine lifted — {state} ({cve_id})"
    body = "\n".join([
        f"Project: {project}",
        f"Quarantined for {cve_id}; this scan found nothing quarantine-level in any",
        "image the project starts, so the quarantine was lifted automatically.",
        "",
        reason,
        "",
        *tail,
        f"Details: boxmunge security {project}",
    ])
    failed = smoke is not None and not smoke[0]
    return Alert(kind="quarantine_lifted", title=title, body=body, priority=1 if failed else 0)


def format_kev_withdrawal_hold_alert(project: str, cve_id: str, source: str) -> Alert:
    """This scan would have lifted the quarantine because a KEV refresh
    withdrew its CVE. One source can do that, so the lift waits for the
    operator. Priority 1: the site stays down until then."""
    return Alert(
        kind="kev_withdrawal_held",
        title=f"[boxmunge:{project}] Quarantine kept — CISA KEV withdrew {cve_id}",
        body="\n".join([
            f"Project: {project}",
            f"Quarantined for {cve_id}. The KEV catalog from {source} no longer",
            "lists it, so nothing else keeps the project quarantined. The images",
            "still contain it, and a single source can drop an entry, so scans and",
            "deploys keep the quarantine. Check CISA's KEV page; if the withdrawal",
            "is real, accept it with:",
            f"  boxmunge security resume {project}",
            f"Details: boxmunge security {project}",
        ]),
        priority=1,
    )
