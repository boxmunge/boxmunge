# SPDX-License-Identifier: Apache-2.0
"""The nightly fleet scan's low-urgency digest, and the nightly autofix's.

These alert kinds are not urgent (new informational findings, a finding
awaiting its fix, a fix to apply, a hardening warning). Some may be worth
acting on, but none quarantines a site tonight, so a fleet scan sends them as ONE quiet message, one line per
project, instead of one push per project. Everything else stays immediate.
"""

from __future__ import annotations

from collections.abc import Sequence

from boxmunge.cve._alerting_types import Alert, AlertKind, Hit

LOW_URGENCY_KINDS: frozenset[AlertKind] = frozenset(
    {"informational", "awaiting_fix", "fix_available", "hardening_upcoming"}
)

# The nightly autofix's outcomes (commands.autofix_nightly): container-update
# sends them as one digest. Not LOW_URGENCY_KINDS: the urgent flow sends the
# same kinds at once, and the scan's digest counts findings, not patches.
NIGHTLY_AUTOFIX_KINDS: frozenset[AlertKind] = frozenset({"autofix_patched", "autofix_failed"})

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
        "None of these quarantines a site.",
        "Details: boxmunge security status",
    ])
    return Alert(kind="scan_digest", title=title, body=body,
                 priority=DIGEST_PRIORITY)


def format_autofix_digest(alerts: Sequence[Alert]) -> Alert:
    """One line per project the nightly autofix tried, patched ones first:
    each alert's title is its line (format_nightly_patched_line,
    format_nightly_failed_line). ``alerts``: at least one, all quiet."""
    if not alerts or not all(a.kind in NIGHTLY_AUTOFIX_KINDS
                             and a.priority == DIGEST_PRIORITY for a in alerts):
        raise ValueError("an autofix digest summarises quiet nightly autofix outcomes only")
    patched = sorted((a for a in alerts if a.kind == "autofix_patched"), key=lambda a: a.project)
    failed = sorted((a for a in alerts if a.kind == "autofix_failed"), key=lambda a: a.project)
    counts = [f"{len(group)} {verb}" for group, verb in
              ((patched, "patched"), (failed, "could not be patched")) if group]
    # "2 projects patched, 1 could not be patched": the noun once, first.
    first = len(patched or failed)
    counts[0] = counts[0].replace(" ", f" project{'s' if first != 1 else ''} ", 1)
    body = "\n".join([
        *(a.title for a in (*patched, *failed)), "",
        "Every site stayed up; a patch that failed was rolled back. The scans keep",
        "alerting a finding until it is fixed.",
        "Details: boxmunge security <project>",
    ])
    return Alert(kind="autofix_digest", title="Nightly autofix: " + ", ".join(counts),
                 body=body, priority=DIGEST_PRIORITY)
