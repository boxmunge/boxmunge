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
the project on other images than before (`on_previous_images`, from the
update's own `recreated`, `rollback_succeeded` and `tags_not_restored`): a
recreate that was not rolled back healthy, a tag not pointed back, or an
update that raised (unknown). An abort before the recreate changed nothing,
so the patch goes ahead. Container-update runs this flow however its run
ends (`nightly_digest`): after a failed Caddy update or a configuration
error too, and when another container-update holds its lock (a dry run or
a single-project run does not autofix the fleet), every project is visited.
An exception that stops the run still sends the digest of the attempts
already made (`send_digest_after_error`).

No patch starts unless AUTOFIX_NIGHTLY_BUDGET plus _START_MARGIN remain of
NIGHTLY_AUTOFIX_WINDOW from container-update's start (the maintenance unit's
own limit covers the scan as well); the projects not reached are deferred
to the next window.

Nothing runs during upgrade probation (even on a forced container-update),
for a project quarantined, migrating or stopped by the health monitor, or
one with an urgent patch queued or an interrupted run's journal left: the
autofix unit (commands.autofix_urgent) owns those. Each skip is logged. A
paused or busy project is not patched either, and is listed in the digest.
A project never scanned is left to the security health check, which
reports it; it is not logged here every night.

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
from boxmunge.container_update import SKIPPED_LOCKED
from boxmunge.cve.alerting import (
    DIGEST_PRIORITY, Alert, format_autofix_digest, format_autofix_failed_alert,
    format_nightly_deferred_line, format_nightly_failed_line, format_nightly_gone_line,
    format_nightly_patched_line, format_nightly_skipped_line, send_alerts,
)
from boxmunge.cve.autofix_policy import (
    AUTOFIX_NIGHTLY_BUDGET, NIGHTLY_AUTOFIX_WINDOW, AutofixUrgency, urgency,
)
from boxmunge.cve.autofix_run import AutofixOutcome, autofix_project_locked
from boxmunge.cve.policy import FindingDisposition
from boxmunge.cve.scan_state import decisions_from_scan_state, read_scan_state
from boxmunge.fileutil import LockError, project_lock
from boxmunge.lifecycle import Block, BlockReason, is_blocked
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
# it, and paused (listed in the digest when it has something to patch); the
# others (quarantined, migrating, monitor-stopped, busy) were skipped by the
# update, which logged why; a busy one is listed by nightly_digest.
_VISITED = frozenset({"succeeded", "no_change", "failed", "paused"})
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


def nightly_digest(paths: BoxPaths, results: Sequence[dict[str, Any]], done: Collection[str],
                   *, only: str | None, until: datetime) -> list[NightlyAttempt]:
    """Container-update's last step, whichever way its run ended: the
    attempts made after the updates (`results`), a line for each project
    still busy after the retry, then the nightly autofix of every deployed
    project not in `done` (not updated tonight); one digest of them all.
    Returns the attempts."""
    attempts = _made(results)
    for r in results:
        if r["status"] == SKIPPED_LOCKED:
            busy = busy_attempt(paths, r["name"])
            if busy is not None:
                attempts.append(busy)
    attempts += autofix_the_rest(paths, done, only=only, until=until)
    send_nightly_results(paths, attempts)
    return attempts


def send_digest_after_error(paths: BoxPaths, results: Sequence[dict[str, Any]],
                            error: BaseException) -> None:
    """Container-update stopped on `error`: the digest of the attempts it
    made. A failure here is noted on `error`, never raised over it."""
    try:
        send_nightly_results(paths, _made(results))
    except Exception as e:  # noqa: BLE001 — the run's own failure is the one raised
        error.add_note(f"the nightly autofix digest could not be sent: {type(e).__name__}: {e}")


def _made(results: Sequence[dict[str, Any]]) -> list[NightlyAttempt]:
    return [r["autofix"] for r in results if r.get("autofix")]


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
            attempt = busy_attempt(paths, project)
        if attempt is not None:
            attempts.append(attempt)
    return attempts


def busy_attempt(paths: BoxPaths, project: str) -> NightlyAttempt | None:
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
    block = is_blocked(project, paths)
    why = _skip_reason(paths, project, block)
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
    not_run = "paused" if block is not None else _not_now(update, until)
    if not_run is not None:
        log_operation(_COMPONENT, f"{project}: nightly autofix skipped: {not_run}", paths,
                      project=project)
        return NightlyAttempt(project, cves, None, not_run)
    started = _now()
    try:
        outcome = autofix_project_locked(paths, project, findings, trigger="nightly",
                                         deadline=started + AUTOFIX_NIGHTLY_BUDGET,
                                         # nightly never patches a quarantined project
                                         quarantined_for_patch=False)
    except Exception as e:  # noqa: BLE001 — rolled back and logged by the runner
        outcome = AutofixOutcome(False, None, f"{type(e).__name__}: {e}", (),
                                 tuple(getattr(e, "__notes__", ())))
    print(f"{project}: nightly autofix " + _said(outcome))
    return NightlyAttempt(project, cves, replace(outcome, started_at=started),
                          updated=update is not None and update["status"] == "succeeded")


def _said(outcome: AutofixOutcome) -> str:
    if outcome.ok:
        return "patched"
    if outcome.nothing_to_patch:
        return f"nothing to patch: {outcome.reason}"
    return f"FAILED at {outcome.failed_step or 'an unexpected error'}: {outcome.reason}"


def _cves(findings: Sequence[FindingDisposition]) -> tuple[str, ...]:
    return tuple(sorted({fd.finding.cve_id for fd in findings}))


def _not_now(update: dict[str, Any] | None, until: datetime) -> str | None:
    """Why the patch does not start now: the update may have changed the
    project, or too little of the window is left."""
    if update is not None and update["status"] == "failed" and not on_previous_images(update):
        return f"container update failed: {update.get('reason')}"
    if until - _now() < AUTOFIX_NIGHTLY_BUDGET + _START_MARGIN:
        return DEFERRED
    return None


def on_previous_images(update: dict[str, Any]) -> bool:
    """A failed update left the project on the images it ran before: every
    tag pointed back, and nothing recreated or rolled back healthy (None:
    unknown, for an update that raised)."""
    return not update["tags_not_restored"] and (
        update["recreated"] is False or update["rollback_succeeded"] is True)


def _skip_reason(paths: BoxPaths, project: str, block: Block | None) -> str | None:
    """Why nothing is tried, not even listed. A paused project is listed
    (run_nightly_autofix), so it is not one of these."""
    if paths.probation.exists():
        return "the platform is in upgrade probation"
    if block is not None and block.reason is not BlockReason.PAUSED:
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
    if state is None:   # the security health check reports a project never scanned
        return []
    decisions = decisions_from_scan_state(state, project_name=project)
    return [fd for d in decisions for fd in d.findings
            if urgency(fd, meta.posture) is AutofixUrgency.NIGHTLY]


def send_nightly_results(paths: BoxPaths, attempts: Sequence[NightlyAttempt]) -> None:
    """One quiet digest of the attempts; a failure whose rollback did not
    finish is the urgent failure alert instead. Best-effort delivery:
    notify logs anything it could not send."""
    lines = [_line(a) for a in attempts]
    quiet = [alert for alert in lines if alert.priority == DIGEST_PRIORITY]
    alerts = (*(alert for alert in lines if alert.priority != DIGEST_PRIORITY),
              *((format_autofix_digest(quiet),) if quiet else ()))
    if not alerts:
        return
    try:
        send_alerts(alerts, paths)
    except Exception as e:  # noqa: BLE001 — alerting must never fail the run
        log_warning(_COMPONENT, f"nightly autofix alert delivery failed: {e}", paths)


def describe(attempt: NightlyAttempt) -> str:
    """The attempt in one line: its digest line, or the urgent alert's title."""
    return _line(attempt).title


def _line(a: NightlyAttempt) -> Alert:
    """The attempt's digest line (quiet), or its urgent alert."""
    o = a.outcome
    if o is None:
        if a.not_run is None:
            raise ValueError(f"{a.project}: a nightly attempt with no outcome says why")
        return (format_nightly_deferred_line(a.project) if a.not_run == DEFERRED
                else format_nightly_skipped_line(a.project, a.not_run))
    if o.rollback_problems:
        return _mixed_alert(a, o)
    if o.ok:
        return format_nightly_patched_line(a.project, a.cves, o.records)
    if o.nothing_to_patch:
        return format_nightly_gone_line(a.project, a.cves, updated=a.updated)
    return format_nightly_failed_line(a.project, step=o.failed_step, reason=o.reason)


def _mixed_alert(a: NightlyAttempt, o: AutofixOutcome) -> Alert:
    started = o.started_at or _now()
    timing = f"Nightly patch started {started:%H:%M} UTC, failed {_now():%H:%M} UTC."
    return format_autofix_failed_alert(
        a.project, a.cves, step=o.failed_step, reason=o.reason,
        site="The site was not quarantined: nightly patches are for findings that keep it up.",
        timing=timing, rollback_problems=o.rollback_problems)
