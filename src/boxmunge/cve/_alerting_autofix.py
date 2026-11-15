# SPDX-License-Identifier: Apache-2.0
"""Autofix alerts: a patch started, a patch running, a patch that failed.

Pure functions, like the other formatters. The urgent flow
(commands.autofix_urgent) sends one notice when it starts patching with the
site up (a quarantine for the patch says so in its own alert), then one
with the outcome; the nightly flow reuses the outcome formatters for
its digest.
"""
from __future__ import annotations

from collections.abc import Sequence

from boxmunge.cve._alerting_types import Alert
from boxmunge.cve.autofix_record import PatchRecord

PERSISTENCE_CAVEAT = ("Autofix replaced the vulnerable code. It does not clean persistent "
                      "data or prove nothing was planted before the patch.")


def _cves(cves: Sequence[str]) -> str:
    return ", ".join(cves)


def format_autofix_started_alert(project: str, cves: Sequence[str], *, downtime: bool) -> Alert:
    """One notice per detection: what was found and whether the site is up."""
    site = "site down while patching" if downtime else "site up"
    line = f"{_cves(cves)} found on {project}, patching ({site})"
    return Alert(kind="autofix_started", title=f"[boxmunge:{project}] {line}", body="\n".join([
        line,
        "",
        "Autofix builds a patched image from the one running, scans it, swaps it in",
        "and checks its health; anything that fails is rolled back. The outcome",
        "follows within 30 minutes.",
        f"Details: boxmunge security {project}",
    ]), priority=0)


def _changes(records: Sequence[PatchRecord]) -> list[str]:
    lines = []
    for r in records:
        changed = ", ".join(f"{p.name} {p.before} → {p.after}" for p in r.packages)
        lines.append(f"- {r.service}: {changed} ({_cves(r.cves)})")
    return lines


def format_autofix_patched_alert(
    project: str, cves: Sequence[str], records: Sequence[PatchRecord], *,
    site: str, timing: str, urgent: bool = False,
) -> Alert:
    """The patched images run. ``site`` says what that means for the site
    (back up, quarantine lifted, or why it stays down); ``timing`` when it
    was found, started and patched; ``urgent`` when it needs the operator
    (a lift that failed, a smoke test that failed)."""
    return Alert(kind="autofix_patched",
                 title=f"[boxmunge:{project}] Autofix patched {_cves(cves)}",
                 body="\n".join([
                     f"Project: {project}",
                     "Patched and running:",
                     *_changes(records),
                     timing,
                     "",
                     site,
                     f"Details: boxmunge security {project}",
                     "",
                     PERSISTENCE_CAVEAT,
                 ]), priority=1 if urgent else 0)


def format_autofix_failed_alert(
    project: str, cves: Sequence[str], *, step: str | None, reason: str, site: str,
    timing: str, rollback_problems: Sequence[str] = (),
) -> Alert:
    """The patch failed and was rolled back; ``site`` is the fallback that
    applies now (flowchart table B). Priority 1."""
    where = f"at the {step} step" if step else "unexpectedly"
    mixed = []
    if rollback_problems:
        mixed = ["", "The rollback did not finish, so the project may be left mixed (its",
                 "previous image pins restored, containers still on a patched image):",
                 *(f"- {p}" for p in rollback_problems),
                 f"Check it with `boxmunge status {project}`; redeploying its release brings",
                 "every service back onto the image the release names."]
    return Alert(kind="autofix_failed",
                 title=f"[boxmunge:{project}] Autofix FAILED {where} — {_cves(cves)}",
                 body="\n".join([
                     f"Project: {project}",
                     f"Autofix of {_cves(cves)} failed {where}: {reason}",
                     timing,
                     *mixed,
                     "",
                     site,
                     "",
                     "To fix it for good, rebuild the image from a base with the fixed",
                     "packages and deploy it.",
                     f"Details: boxmunge security {project}",
                 ]), priority=1)
