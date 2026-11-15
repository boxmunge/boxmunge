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
NIGHTLY_AUTOFIX_KINDS: frozenset[AlertKind] = frozenset(
    {"autofix_patched", "autofix_gone", "autofix_failed", "autofix_skipped", "autofix_deferred"})

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
    """One line per project the nightly autofix visited with something to
    patch, and per pinned service it caught up with upstream: patched (or
    re-patched on a new upstream image), already fixed (nothing left to
    patch, or switched to upstream), could not patch (or catch up), skipped,
    deferred; by project within each, each count a count of projects. Each alert's title is
    its line (_alerting_autofix.format_nightly_*). ``alerts``: at least one,
    all quiet."""
    if not alerts or not all(a.kind in NIGHTLY_AUTOFIX_KINDS
                             and a.priority == DIGEST_PRIORITY for a in alerts):
        raise ValueError("an autofix digest summarises quiet nightly autofix outcomes only")
    groups = [sorted((a for a in alerts if a.kind == kind), key=lambda a: a.project)
              for kind, _ in _AUTOFIX_GROUPS]
    # Projects, not lines: one project can have a line per service caught up
    # with upstream as well as its own.
    counts = [f"{len({a.project for a in group})} {verb}"
              for group, (_, verb) in zip(groups, _AUTOFIX_GROUPS) if group]
    # "2 projects patched, 1 could not be patched": the noun once, first.
    first = len({a.project for a in next(group for group in groups if group)})
    counts[0] = counts[0].replace(" ", f" project{'s' if first != 1 else ''} ", 1)
    body = "\n".join([
        *(a.title for group in groups for a in group), "",
        "Every site stayed up; a patch that failed was rolled back. The scans keep",
        "alerting a finding until it is fixed.",
        "Details: boxmunge security <project>",
    ])
    return Alert(kind="autofix_digest", title="Nightly autofix: " + ", ".join(counts),
                 body=body, priority=DIGEST_PRIORITY)


# (kind, how its count reads), in digest order.
_AUTOFIX_GROUPS: tuple[tuple[AlertKind, str], ...] = (
    ("autofix_patched", "patched"),
    ("autofix_gone", "already fixed"),
    ("autofix_failed", "could not be patched"),
    ("autofix_skipped", "skipped"),
    ("autofix_deferred", "deferred"),
)
