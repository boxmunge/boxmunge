# SPDX-License-Identifier: Apache-2.0
"""The nightly fleet scan's low-urgency digest.

Nothing in these alert kinds needs doing tonight (new informational
findings, a finding awaiting its fix, a fix to apply, a hardening
warning), so a fleet scan sends them as ONE quiet message, one line per
project, instead of one push per project. Everything else stays immediate.
"""

from __future__ import annotations

from collections.abc import Sequence

from boxmunge.cve._alerting_types import Alert, AlertKind, Hit

LOW_URGENCY_KINDS: frozenset[AlertKind] = frozenset(
    {"informational", "awaiting_fix", "fix_available", "hardening_upcoming"}
)

# Pushover priority -1: delivered without sound or vibration.
DIGEST_PRIORITY = -1


def is_low_urgency(alert: Alert) -> bool:
    return alert.kind in LOW_URGENCY_KINDS


def format_scan_digest(alerts: Sequence[Alert]) -> Alert:
    """One line per project: ``project: N new, highest <severity>``.

    ``alerts`` are the low-urgency alerts collected over the fleet run
    (at least one; a digest of nothing is never sent).
    """
    if not alerts or not all(is_low_urgency(a) for a in alerts):
        raise ValueError("a scan digest summarises low-urgency alerts only")
    by_project: dict[str, list[Hit]] = {}
    for alert in alerts:
        by_project.setdefault(alert.project, []).extend(alert.hits)
    lines = []
    for project in sorted(by_project):
        hits = by_project[project]
        top = max((h.disposition.effective_severity for h in hits),
                  key=lambda sev: sev.rank)
        lines.append(f"{project}: {len(hits)} new, highest {top.value}")
    n = len(lines)
    title = f"Nightly CVE scan: new findings in {n} project{'s' if n != 1 else ''}"
    body = "\n".join([
        *lines, "",
        "None of these quarantines a site, and none needs doing now.",
        "Details: boxmunge security status",
    ])
    return Alert(kind="scan_digest", title=title, body=body,
                 priority=DIGEST_PRIORITY)
