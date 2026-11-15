# SPDX-License-Identifier: Apache-2.0
"""The nightly autofix flow: patch, in the maintenance window, the fixable
findings that are not known exploited (CVE autofix design, "Non-KEV flow").

The maintenance unit runs the fleet scan, then container-update. Every
deployed project with `security.autofix` on is visited, whether or not its
containers are updated (container updates switched off for it or for the
box change nothing here; `security.autofix: false` is the only opt-out):
after a project's own container update, under the same project lock
(container_update_cmd.update_project), or, for one container-update does
not update, under its lock taken here (`autofix_the_rest`). The project's
findings are read from the scan it stored, and those
`cve.autofix_policy.urgency` calls NIGHTLY (on the patch path, at or above
what the posture alerts on, balanced's threshold under relaxed, not
suppressed, not listed) are patched by cve.autofix_run with the site up, by
a deadline AUTOFIX_NIGHTLY_BUDGET after the attempt's own start. The runner
scans the running images again first, so a project the update just moved
onto a new upstream image is patched on that image; when that image no
longer has the CVEs, the digest says so ("fixed by tonight's update").

A failed container update holds the patch back only when it may have left
the project on other images than before: a recreate that was not rolled
back healthy, a tag not pointed back, or an error of unknown extent. A pull,
backup or gate failure changed nothing, so the patch goes ahead.

No patch starts unless AUTOFIX_NIGHTLY_BUDGET plus _START_MARGIN remain of
NIGHTLY_AUTOFIX_WINDOW from container-update's start (the maintenance unit's
own limit covers the scan as well); the projects not reached are deferred
to the next window.

Nothing runs during upgrade probation (even on a forced container-update),
for a project quarantined, paused, migrating or stopped by the health
monitor, or one with an urgent patch queued or an interrupted run's journal
left: the autofix unit (commands.autofix_urgent) owns those. Each skip is
logged.

The outcomes go out as ONE quiet digest from container-update (priority -1),
one line per project: patched, fixed by tonight's update (or no longer in
the running images), could not patch, skipped, deferred. Skips and deferrals
are listed only for a project that had something to patch. A failure whose
rollback did not finish may leave the project mixed: it is the urgent
failure alert, at once, never quiet.
"""
from __future__ import annotations

import os
from collections.abc import Collection, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.commands.security_scan_inputs import ProjectScanError, load_project_meta
from boxmunge.cve.alerting import (
    Alert, format_autofix_digest, format_autofix_failed_alert, format_nightly_failed_line,
    format_nightly_deferred_line, format_nightly_gone_line, format_nightly_patched_line,
    format_nightly_skipped_line, send_alerts,
)
from boxmunge.cve.autofix_policy import (
    AUTOFIX_NIGHTLY_BUDGET, NIGHTLY_AUTOFIX_WINDOW, AutofixUrgency, urgency,
)
from boxmunge.cve.autofix_run import AutofixOutcome, autofix_project_locked
from boxmunge.cve.policy import FindingDisposition
from boxmunge.cve.scan_state import decisions_from_scan_state, read_scan_state
from boxmunge.fileutil import LockError, project_lock
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.manifest import ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.project_inventory import Inventory, classify, project_dir_names
from boxmunge.state import StateError

_COMPONENT = "autofix"
_READ_PROBLEMS = (StateError, ValueError, KeyError, TypeError, ManifestError,
                  ProjectScanError, OSError)
# A patch starts only with this much more than its budget left of the window.
_START_MARGIN = timedelta(minutes=10)
# Container update statuses after which the project runs as the update left
# it; the others (quarantined, paused, migrating, monitor-stopped, busy)
# were skipped by the update, which logged why.
_VISITED = frozenset({"succeeded", "no_change", "failed"})
# A failed update with one of these reasons recreated nothing (it aborted
# before the recreate, its tags pointed back).
_NOTHING_RECREATED = ("pull_failed", "inventory_failed", "user_changed", "backup_failed",
                      "refused")
DEFERRED = "deferred to the next maintenance window"


@dataclass(frozen=True)
class NightlyAttempt:
    """One project's nightly patch: the CVEs it was for, and its outcome;
    or, `outcome` None, why it did not run (`not_run`). `updated`: tonight's
    container update moved the project onto new images first."""
    project: str
    cves: tuple[str, ...]
    outcome: AutofixOutcome | None
    not_run: str | None = None
    updated: bool = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def window_end() -> datetime:
    """When this container-update's nightly autofix window closes."""
    return _now() + NIGHTLY_AUTOFIX_WINDOW


def after_update(paths: BoxPaths, project: str, result: dict[str, Any], *,
                 until: datetime) -> NightlyAttempt | None:
    """Container-update's hook, under the project lock it updated under."""
    if result["status"] not in _VISITED:
        return None
    return run_nightly_autofix(paths, project, until=until, update=result)


def autofix_the_rest(paths: BoxPaths, done: Collection[str], *, only: str | None,
                     until: datetime) -> list[NightlyAttempt]:
    """The nightly autofix of every deployed project not in `done` (those
    container-update did not update; just `only` when given), each under
    its project lock."""
    names = [only] if only is not None else project_dir_names(paths)
    attempts = []
    for project in names:
        if project in done or classify(project, paths) is not Inventory.DEPLOYED:
            continue
        try:
            with project_lock(project, paths):
                attempt = run_nightly_autofix(paths, project, until=until)
        except LockError:
            attempt = _busy(paths, project)
        if attempt is not None:
            attempts.append(attempt)
    return attempts


def _busy(paths: BoxPaths, project: str) -> NightlyAttempt | None:
    """The project is locked: listed when it has something to patch (read
    without the lock, for the digest only)."""
    try:
        cves = _cves(_nightly_findings(paths, project))
    except _READ_PROBLEMS:
        cves = ()
    log_operation(_COMPONENT, f"{project}: nightly autofix skipped: another operation holds "
                  f"the project", paths, project=project)
    if not cves:
        return None
    return NightlyAttempt(project, cves, None, "another operation holds the project; the "
                          "next window tries again")


def run_nightly_autofix(paths: BoxPaths, project: str, *, until: datetime,
                        update: dict[str, Any] | None = None) -> NightlyAttempt | None:
    """Patch the project's nightly findings, unless the window closes too
    soon (`until`) or tonight's container `update` result rules it out;
    None when there is nothing to run. The caller holds the project lock
    (the runner checks)."""
    why = _skip_reason(paths, project)
    if why is not None:
        log_operation(_COMPONENT, f"{project}: nightly autofix skipped: {why}", paths,
                      project=project)
        return None
    try:
        findings = _nightly_findings(paths, project)
    except _READ_PROBLEMS as e:
        reason = f"its stored scan or manifest cannot be read: {type(e).__name__}: {e}"
        log_error(_COMPONENT, f"{project}: nightly autofix could not run: {reason}", paths,
                  project=project)
        return NightlyAttempt(project, (), AutofixOutcome(False, None, reason, ()))
    if not findings:
        return None
    cves = _cves(findings)
    not_run = _not_now(update, until)
    if not_run is not None:
        log_operation(_COMPONENT, f"{project}: nightly autofix skipped: {not_run}", paths,
                      project=project)
        return NightlyAttempt(project, cves, None, not_run)
    started = _now()
    try:
        outcome = autofix_project_locked(paths, project, findings, trigger="nightly",
                                         deadline=started + AUTOFIX_NIGHTLY_BUDGET)
    except Exception as e:  # noqa: BLE001 — rolled back and logged by the runner
        outcome = AutofixOutcome(False, None, f"{type(e).__name__}: {e}", (),
                                 tuple(getattr(e, "__notes__", ())))
    print(f"{project}: nightly autofix " + ("patched" if outcome.ok else
          f"FAILED at {outcome.failed_step or 'an unexpected error'}: {outcome.reason}"))
    return NightlyAttempt(project, cves, replace(outcome, started_at=started),
                          updated=update is not None and update["status"] == "succeeded")


def _cves(findings: Sequence[FindingDisposition]) -> tuple[str, ...]:
    return tuple(sorted({fd.finding.cve_id for fd in findings}))


def _not_now(update: dict[str, Any] | None, until: datetime) -> str | None:
    """Why the patch does not start now: the update may have changed the
    project, or too little of the window is left."""
    if update is not None and update["status"] == "failed" and not _on_previous_images(update):
        return f"container update failed: {update.get('reason')}"
    if until - _now() < AUTOFIX_NIGHTLY_BUDGET + _START_MARGIN:
        return DEFERRED
    return None


def _on_previous_images(update: dict[str, Any]) -> bool:
    """A failed update left the project on the images it ran before."""
    if update.get("tags_not_restored"):
        return False
    reason = str(update.get("reason") or "")
    return reason.startswith(_NOTHING_RECREATED) or update.get("rollback_succeeded") is True


def _skip_reason(paths: BoxPaths, project: str) -> str | None:
    if paths.probation.exists():
        return "the platform is in upgrade probation"
    block = is_blocked(project, paths)
    if block is not None:
        return f"the project is {block.reason.value}"
    if is_monitor_stopped(project, paths):
        return "the project was stopped by the health monitor"
    if os.path.lexists(paths.project_autofix_queue(project)):
        return "an urgent patch is queued for it, which the autofix unit runs"
    if os.path.lexists(paths.project_autofix_journal(project)):
        return "an interrupted autofix run left its journal, which the autofix unit undoes"
    return None


def _nightly_findings(paths: BoxPaths, project: str) -> list[FindingDisposition]:
    """The findings of the stored scan to patch tonight. Raises what the
    reads raise (_READ_PROBLEMS)."""
    meta = load_project_meta(paths, project)
    if not meta.autofix:
        return []
    state = read_scan_state(paths.project_scan_state(project))
    if state is None:
        log_warning(_COMPONENT, f"{project}: no stored scan, so nightly autofix has nothing "
                    f"to judge", paths, project=project)
        return []
    decisions = decisions_from_scan_state(state, project_name=project)
    return [fd for d in decisions for fd in d.findings
            if urgency(fd, meta.posture) is AutofixUrgency.NIGHTLY]


def send_nightly_results(paths: BoxPaths, attempts: Sequence[NightlyAttempt]) -> None:
    """One quiet digest of the attempts; a failure whose rollback did not
    finish is the urgent failure alert instead. Best-effort delivery:
    notify logs anything it could not send."""
    quiet: list[Alert] = []
    loud: list[Alert] = []
    for a in attempts:
        o = a.outcome
        if o is None:
            quiet.append(format_nightly_deferred_line(a.project) if a.not_run == DEFERRED
                         else format_nightly_skipped_line(a.project, a.not_run or ""))
        elif o.ok:
            quiet.append(format_nightly_patched_line(a.project, a.cves, o.records))
        elif o.nothing_to_patch and not o.rollback_problems:
            quiet.append(format_nightly_gone_line(a.project, a.cves, updated=a.updated))
        elif o.rollback_problems:
            loud.append(_mixed_alert(a, o))
        else:
            quiet.append(format_nightly_failed_line(a.project, step=o.failed_step,
                                                    reason=o.reason))
    alerts = (*loud, *((format_autofix_digest(quiet),) if quiet else ()))
    if not alerts:
        return
    try:
        send_alerts(alerts, paths)
    except Exception as e:  # noqa: BLE001 — alerting must never fail the run
        log_warning(_COMPONENT, f"nightly autofix alert delivery failed: {e}", paths)


def _mixed_alert(a: NightlyAttempt, o: AutofixOutcome) -> Alert:
    started = o.started_at or _now()
    timing = f"Nightly patch started {started:%H:%M} UTC, failed {_now():%H:%M} UTC."
    return format_autofix_failed_alert(
        a.project, a.cves, step=o.failed_step, reason=o.reason,
        site="The site was not quarantined: nightly patches are for findings that keep it up.",
        timing=timing, rollback_problems=o.rollback_problems)
