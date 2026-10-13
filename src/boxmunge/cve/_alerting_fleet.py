# SPDX-License-Identifier: Apache-2.0
"""Fleet-level alert formatters: one alert per scan run, not per project.

Pure functions: in-memory values in, ``Alert`` out. Consumers import them
from ``boxmunge.cve.alerting``.
"""
from __future__ import annotations

from datetime import datetime

from boxmunge.cve._alerting_types import Alert

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
        title = "[boxmunge] CISA KEV feed stale — exploitation defense degraded"
        state = "The cached CISA Known Exploited Vulnerabilities catalog is stale or missing."
    else:
        title = "[boxmunge] CISA KEV refresh rejected — previous catalog kept"
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
        f"[boxmunge] CVE scan incomplete — {n} project"
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
