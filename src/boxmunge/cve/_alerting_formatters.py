# SPDX-License-Identifier: Apache-2.0
"""Per-project alert formatters for CVE policy state transitions.

One alert per project per kind of transition, never one per finding
(audit B-14): a project's first scan, or an image rebuild, can surface
dozens of findings at once, and a storm of pushes trains operators to
ignore the channel that carries quarantine alerts.

Pure functions: take in-memory values, return ``Alert`` instances. No I/O,
no logging. Fleet-level formatters (grace heads-up, KEV, scan failure)
live in ``_alerting_fleet``; consumers import from ``boxmunge.cve.alerting``.
"""

from __future__ import annotations

from collections.abc import Sequence

from boxmunge.cve._alerting_types import Alert, Hit
from boxmunge.cve.policy import FindingDisposition
from boxmunge.cve.scanner import Severity
from boxmunge.cve.suppressions import Suppression

# Lines listed in an aggregated alert body before "... and N more".
_MAX_LISTED = 10
# Findings named in the informational digest.
_DIGEST_TOP = 5

_RANK = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
         Severity.LOW: 1, Severity.UNKNOWN: 0}


def _ordered(hits: Sequence[Hit]) -> list[Hit]:
    """Most severe first, then by CVE id, for stable titles and bodies."""
    return sorted(hits, key=lambda h: (-_RANK[h.disposition.effective_severity],
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
    """Findings over the quarantine gate whose fix the image is not running.
    Not quarantined (the fix is the remedy), never silent. Priority 0."""
    hits = _ordered(hits)
    n = len(hits)
    title = (f"[boxmunge:{project}] {n} fixable CVE finding{'s' if n != 1 else ''} "
             f"over the quarantine gate — rebuild to apply the fix")
    body = "\n".join([
        f"Project: {project}",
        "A fix exists for each of these, but the running image predates it:",
        *_listing(hits),
        "",
        "boxmunge does not rebuild images. Rebuild (pull the base image) and",
        "redeploy to pick up the fixes.",
    ])
    return Alert(kind="fix_available", title=title, body=body, priority=0)


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
