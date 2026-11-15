# SPDX-License-Identifier: Apache-2.0
"""Autofix alerts: a patch started, a patch running, a patch that failed.

Pure functions, like the other formatters. The urgent flow
(commands.autofix_urgent) sends one notice when it starts patching with the
site up (a quarantine for the patch says so in its own alert), then one
with the outcome. The nightly flow (commands.autofix_nightly) puts each
outcome on one line of a quiet digest (cve._alerting_digest), except a
failure whose rollback did not finish, which is the urgent failure alert.
"""
from __future__ import annotations

from collections.abc import Sequence

from boxmunge.cve._alerting_digest import DIGEST_PRIORITY
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


def format_autofix_interrupted_alert(project: str, problems: Sequence[str], *,
                                     site: str) -> Alert:
    """A run was killed mid-swap (its journal was left) and has now been
    rolled back from the journal; ``site`` is the fallback applied for what
    it was patching. Priority 1."""
    undone = (["", "The rollback did not finish:", *(f"- {p}" for p in problems),
               f"Check it with `boxmunge status {project}`."] if problems else [])
    return Alert(kind="autofix_failed",
                 title=f"[boxmunge:{project}] Autofix run interrupted — rolled back",
                 body="\n".join([
                     f"An autofix run for {project} was interrupted and has been rolled back:",
                     "its previous image pins are restored, its containers recreated and the",
                     "images it built removed.",
                     *undone,
                     "",
                     site,
                     f"Details: boxmunge security {project}",
                 ]), priority=1)


def format_nightly_patched_line(project: str, cves: Sequence[str],
                                records: Sequence[PatchRecord]) -> Alert:
    """A nightly patch that runs: one digest line, its title."""
    n = sum(len(r.packages) for r in records)
    line = f"patched: {project}: {_cves(cves)} ({n} package{'s' if n != 1 else ''})"
    return Alert(kind="autofix_patched", title=line, body=line, priority=DIGEST_PRIORITY,
                 project=project)


def format_nightly_gone_line(project: str, cves: Sequence[str], *, updated: bool) -> Alert:
    """The CVEs are no longer in the images the project runs (``updated``:
    tonight's container update replaced them): nothing to patch, not a
    failure. One digest line, its title."""
    where = "fixed by tonight's update" if updated else "no longer in the running images"
    line = f"{where}: {project}: {_cves(cves)}"
    return Alert(kind="autofix_gone", title=line, body=line, priority=DIGEST_PRIORITY,
                 project=project)


def format_nightly_skipped_line(project: str, why: str) -> Alert:
    """A nightly patch that did not start, and why. One digest line, its title."""
    line = f"skipped: {project}: {why}"
    return Alert(kind="autofix_skipped", title=line, body=line, priority=DIGEST_PRIORITY,
                 project=project)


def format_nightly_deferred_line(project: str) -> Alert:
    """A nightly patch not started: too little of the window was left. One
    digest line, its title."""
    line = f"deferred to the next maintenance window: {project}"
    return Alert(kind="autofix_deferred", title=line, body=line, priority=DIGEST_PRIORITY,
                 project=project)


def format_nightly_failed_line(project: str, *, step: str | None, reason: str) -> Alert:
    """A nightly patch that failed and was rolled back cleanly: one digest
    line, its title."""
    line = f"could not patch: {project}: {step or 'unexpected error'}: {reason}"
    return Alert(kind="autofix_failed", title=line, body=line, priority=DIGEST_PRIORITY,
                 project=project)


def format_upstream_switched_line(project: str, service: str) -> Alert:
    """A pinned service's new upstream image is clean: it runs it, and its
    patch is gone (counted with the already fixed). One digest line."""
    line = f"switched to upstream: {project}/{service}"
    return Alert(kind="autofix_gone", title=line, body=line, priority=DIGEST_PRIORITY,
                 project=project)


def format_upstream_repatched_line(project: str, service: str) -> Alert:
    """A pinned service's new upstream image still needed the patch: it was
    patched again from that image. One digest line."""
    line = f"re-patched on new upstream: {project}/{service}"
    return Alert(kind="autofix_patched", title=line, body=line, priority=DIGEST_PRIORITY,
                 project=project)


def format_upstream_failed_line(project: str, service: str | None, reason: str) -> Alert:
    """Catching a pinned service up with upstream failed and was rolled back
    cleanly; it keeps its patch. One digest line."""
    line = f"could not catch up with upstream: {project}{'/' + service if service else ''}: " \
           f"{reason}"
    return Alert(kind="autofix_failed", title=line, body=line, priority=DIGEST_PRIORITY,
                 project=project)
