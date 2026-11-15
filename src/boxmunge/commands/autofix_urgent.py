# SPDX-License-Identifier: Apache-2.0
"""The urgent autofix flow's run: patch what the scan queued, then apply the
outcome (CVE autofix flowcharts, chart 1 and table B).

A scan or KEV watch tick queues a patch (commands.autofix_urgent_scan);
the queue runs in its own unit, boxmunge-autofix.service, which a caller
running as root starts without waiting (commands.autofix_queue_cmd), so a
long patch never runs inside the watch's or the nightly unit's timeout,
and never holds the fleet lock. For each queued project, under its project
lock (held by someone else: left for the next run, logged):

- a journal left by a run that was killed (cve.autofix_run) is undone
  first, alerted once, and table B applied for what it was patching; then
  the queued patch carries on as below;
- the findings are read again from the project's stored scan, by the keys
  the queue holds: a queue entry is never trusted on its own. Gone (a later
  scan no longer finds them, or they stopped being urgent): the entry and
  the marker are dropped and nothing runs; a quarantine taken for them
  follows the scan's own lift rules;
- cve.autofix_run patches, swaps and health checks, and rolls back on any
  failure, by a deadline AUTOFIX_URGENT_BUDGET after this attempt's own
  start: with many projects queued at once (one base image), a project
  waiting its turn stays as the scan left it (up and marked autofixing, or
  quarantined), and does not lose its patch to the wait. The detection and
  start times are in the outcome, the oplog and the alert.

Success lifts the quarantine taken for the patch (the scan's lift path,
quarantine_lift.restore_from_quarantine), and one quiet notice says so: the
lift sends no alert of its own. Failure applies table B, which is the
policy's own disposition of the findings: one the policy takes down is
quarantined (re-asserted when it is already: the rollback started the
containers), one it leaves up or at risk stays so; then one urgent alert
names the step. The lift or the fallback comes first, then the entry and
the marker are cleared (both kept when the lift or the fallback failed, so
the next run retries), then the one alert, which says what of that
failed. Upgrade probation does not hold this back; only the nightly flow
waits for it.

A queue entry that cannot be read is logged on every run, alerted at most
once a day per project, and skipped; the rest of the queue still runs.
`only` limits a run to some projects: a single-project `security scan`
run as deploy runs its own project's entry itself, at once.
"""
from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from boxmunge.commands.autofix_urgent_scan import with_note
from boxmunge.commands.quarantine_lift import Restored, restore_from_quarantine
from boxmunge.commands.security_enforce import quarantine_listing
from boxmunge.commands.security_scan_inputs import (
    ProjectMeta, ProjectScanError, load_project_meta,
)
from boxmunge.cve.alerting import (
    Alert, format_autofix_failed_alert, format_autofix_interrupted_alert,
    format_autofix_patched_alert, send_alerts,
)
from boxmunge.cve.autofix_policy import AUTOFIX_URGENT_BUDGET, AutofixUrgency, urgency
from boxmunge.cve.autofix_record import (
    QueueEntry, clear_autofixing, journaled_projects, queued_projects, read_queue_entry,
    remove_queue_entry,
)
from boxmunge.cve.autofix_run import (
    AutofixOutcome, autofix_project_locked, recover_interrupted,
)
from boxmunge.cve.breaker import BreakerError, read_held
from boxmunge.cve.policy import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.quarantine import (
    QuarantineError, quarantine_project, read_quarantine_state, reassert_quarantine,
)
from boxmunge.cve.scan_state import decisions_from_scan_state, read_scan_state
from boxmunge.fileutil import LockError, project_lock
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.manifest import ManifestError
from boxmunge.paths import BoxPaths, InvalidProjectName
from boxmunge.project_alerts import alert_once
from boxmunge.state import StateError

_COMPONENT = "autofix"
_PROBLEMS = (StateError, ValueError, KeyError, TypeError, ManifestError, ProjectScanError,
             OSError)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def run_urgent_queue(paths: BoxPaths, now: datetime, *,
                     only: Collection[str] | None = None) -> list[AutofixOutcome]:
    """Run every queued urgent patch (of ``only``, when given), and undo any
    run that was killed (a journal left behind); the outcome of each patch
    that ran. ``now``: the earliest the run can start."""
    try:
        projects = sorted(set(queued_projects(paths)) | set(journaled_projects(paths)))
    except StateError as e:
        _problem(paths, None, str(e))
        return []
    outcomes = []
    for project in projects:
        if only is not None and project not in only:
            continue
        try:
            with project_lock(project, paths):
                outcome = _process(paths, project, max(now, _now()))
        except LockError:
            log_operation(_COMPONENT, f"{project}: queued autofix left for the next run: the "
                          f"project is held by another operation", paths, project=project)
            continue
        except InvalidProjectName as e:
            _problem(paths, None, f"the autofix queue holds {project!r}, not a project "
                     f"name: {e}")
            continue
        if outcome is not None:
            print(f"{project}: autofix " + ("patched" if outcome.ok else
                  f"FAILED at {outcome.failed_step or 'an unexpected error'}: {outcome.reason}"))
            outcomes.append(outcome)
    return outcomes


def _problem(paths: BoxPaths, project: str | None, problem: str) -> None:
    """A queue entry or the state it needs is unusable: logged on every run,
    alerted at most once a day per project (a name that is not a project's
    has no per-project record to throttle by: logged only)."""
    log_error(_COMPONENT, f"urgent autofix{f' of {project}' if project else ''} could not run: "
              f"{problem}", paths, project=project)
    if project is None:
        return
    alert_once(paths, project, "autofix-queue", {"day": _now().date().isoformat()},
               title=f"[boxmunge:{project}] Urgent autofix could not run", priority=1,
               component=_COMPONENT, message="\n".join([
                   problem, "",
                   "Nothing was patched; what the scan decided stands. Fix or remove the",
                   f"entry under {paths.autofix_queue_dir}; the next scan queues the",
                   "patch again. Alerted once a day while it lasts.",
               ]))


def _send(paths: BoxPaths, alert: Alert) -> None:
    try:
        send_alerts((alert,), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block the flow
        log_warning(_COMPONENT, f"autofix alert delivery failed: {e}", paths)


@dataclass(frozen=True)
class _Job:
    """A queued patch, read again: the entry, and what the stored scan
    still holds of it."""
    entry: QueueEntry
    meta: ProjectMeta
    decisions: tuple[ProjectDecision, ...]
    findings: list[FindingDisposition]


def _read(paths: BoxPaths, project: str) -> _Job | None:
    """The project's queued patch, or None. Raises what its reads raise
    (_PROBLEMS): the entry stays, and nothing was changed."""
    entry = read_queue_entry(paths, project)
    if entry is None:
        return None
    meta = load_project_meta(paths, project)
    state = read_scan_state(paths.project_scan_state(project))
    if state is None:
        raise StateError(f"{project} has an autofix queued but no stored scan")
    decisions = decisions_from_scan_state(state, project_name=project)
    return _Job(entry, meta, decisions, _current(decisions, entry, meta))


def _current(decisions: Sequence[ProjectDecision], entry: QueueEntry,
             meta: ProjectMeta) -> list[FindingDisposition]:
    """The queued findings the stored scan still holds, and still urgent."""
    keys = {(f.cve_id, f.package, f.image_ref) for f in entry.findings}
    return [fd for d in decisions for fd in d.findings
            if (fd.finding.cve_id, fd.finding.package, d.image_ref) in keys
            and urgency(fd, meta.posture) is AutofixUrgency.URGENT]


def _done(paths: BoxPaths, project: str) -> None:
    remove_queue_entry(paths, project)
    clear_autofixing(paths, project)


def _dark(paths: BoxPaths, project: str) -> tuple[str, ...]:
    """The CVEs of the queued patch when it took the project down
    (quarantined it), so undoing a killed run may start it behind its
    maintenance page; else (). An entry that cannot be read gives (): the
    undo then starts nothing, and _read alerts the entry."""
    try:
        entry = read_queue_entry(paths, project)
    except StateError:
        return ()
    return entry.cves if entry is not None and entry.downtime else ()


def _process(paths: BoxPaths, project: str, now: datetime) -> AutofixOutcome | None:
    """Under the project lock: undo a killed run, read the queued patch
    (a read that fails is alerted and changes nothing), run it, conclude."""
    try:
        interrupted = recover_interrupted(
            paths, project, patch_cves=_dark(paths, project))
    except StateError as e:
        _problem(paths, project, f"its autofix journal cannot be used: {e}")
        return None
    unreadable = None
    try:
        job = _read(paths, project)
    except _PROBLEMS as e:
        unreadable = f"{type(e).__name__}: {e}"
        _problem(paths, project, unreadable)
        job = None
    if interrupted is not None:
        if unreadable is not None:
            site = (f"Its queued patch cannot be read ({unreadable}), so no fallback was "
                    f"applied for it; a separate alert names the problem.")
        elif job is None or not job.findings:
            site = "Nothing it was patching is queued any more."
        else:
            site = _fallback(paths, project, job)[0]
        _send(paths, format_autofix_interrupted_alert(project, interrupted, site=site))
    if job is None:
        return None
    if not job.findings:
        try:
            _done(paths, project)
        except StateError as e:   # logged; never stops the rest of the queue
            log_error(_COMPONENT, f"{project}: dropping its stale queued autofix failed: {e}",
                      paths, project=project)
            return None
        log_operation(_COMPONENT, f"{project}: queued autofix of {', '.join(job.entry.cves)} "
                      f"dropped: the stored scan no longer has them to patch", paths,
                      project=project)
        return None
    entry = job.entry
    log_operation(_COMPONENT, f"{project}: urgent autofix of {', '.join(entry.cves)} "
                  f"starting, found {entry.detected_at.isoformat()}", paths, project=project,
                  detail={"detected_at": entry.detected_at.isoformat(),
                          "started_at": now.isoformat()})
    if not job.meta.autofix:
        outcome = AutofixOutcome(False, None, "autofix was turned off for this project "
                                 "before the patch started", ())
    else:
        outcome = _patch(paths, project, job.findings, now + AUTOFIX_URGENT_BUDGET,
                         downtime=entry.downtime)
    outcome = replace(outcome, detected_at=entry.detected_at, started_at=now)
    _conclude(paths, project, job, outcome)
    return outcome


def _conclude(paths: BoxPaths, project: str, job: _Job, outcome: AutofixOutcome) -> None:
    """Lift or fall back first, then clear the entry and the marker (kept
    when the lift or the fallback failed, so the next run retries), then
    one alert saying all of it."""
    cves = sorted({fd.finding.cve_id for fd in job.findings})
    timing = _timing(job.entry.detected_at, outcome.started_at or _now(), _now(),
                     "patched" if outcome.ok else "failed")
    log_operation(_COMPONENT, f"{project}: urgent autofix of {', '.join(cves)}: {timing}",
                  paths, project=project, detail={
                      "ok": outcome.ok, "detected_at": job.entry.detected_at.isoformat(),
                      "started_at": (outcome.started_at or _now()).isoformat()})
    if outcome.ok:
        site, settled, urgent = _succeeded(paths, project, job)
        alert = format_autofix_patched_alert(project, cves, outcome.records, site=site,
                                             urgent=urgent, timing=timing)
    else:
        site, settled = _fallback(paths, project, job)
        alert = format_autofix_failed_alert(
            project, cves, step=outcome.failed_step, reason=outcome.reason, site=site,
            rollback_problems=outcome.rollback_problems, timing=timing)
    note = None
    if not settled:
        note = "The patch stays queued (and marked), so the next autofix run tries again."
    else:
        try:
            _done(paths, project)
        except StateError as e:
            log_error(_COMPONENT, f"{project}: {e}", paths, project=project)
            note = f"Clearing the queue entry or the autofixing marker failed: {e}"
    _send(paths, with_note(alert, note))


def _timing(found: datetime, started: datetime, ended: datetime, verb: str) -> str:
    """"Found 12:03 UTC, patch started 12:20, patched 12:21" (with the date
    when the times span days)."""
    fmt = "%H:%M" if found.date() == ended.date() else "%Y-%m-%d %H:%M"
    return (f"Found {found.astimezone(timezone.utc):{fmt}} UTC, patch started "
            f"{started.astimezone(timezone.utc):{fmt}}, {verb} "
            f"{ended.astimezone(timezone.utc):{fmt}}.")


def _patch(paths: BoxPaths, project: str, findings: Sequence[FindingDisposition],
           deadline: datetime, *, downtime: bool) -> AutofixOutcome:
    """The runner's outcome; an exception no step expects (rolled back, and
    logged by the runner) is a failure too, so the fallback still applies."""
    try:
        return autofix_project_locked(paths, project, findings, trigger="urgent",
                                      deadline=deadline, quarantined_for_patch=downtime)
    except Exception as e:  # noqa: BLE001 — the fallback must apply whatever failed
        notes = tuple(getattr(e, "__notes__", ()))
        return AutofixOutcome(False, None, f"{type(e).__name__}: {e}", (), notes)


def _quarantine_kwargs(paths: BoxPaths, project: str, meta: ProjectMeta) -> dict:
    return {"project_dir": paths.project_dir(project), "hosts": meta.hosts,
            "compose_files": meta.compose_files}


def _succeeded(paths: BoxPaths, project: str, job: _Job) -> tuple[str, bool, bool]:
    """Lift the quarantine taken for the patch. (what the site is now,
    whether that is settled, whether it needs the operator)."""
    try:
        record = read_quarantine_state(project, paths)
    except QuarantineError as e:
        return f"Whether the project is quarantined cannot be read: {e}", False, True
    if record is None:
        return "The site stayed up while it was patched.", True, False
    if record.get("cve_id") in job.entry.cves:
        try:
            site, urgent = _lifted(restore_from_quarantine(paths, project,
                                                           component=_COMPONENT))
        except QuarantineError as e:
            log_error(_COMPONENT, f"{project}: quarantine lift after autofix failed: {e}",
                      paths, project=project)
            return (f"The quarantine could not be lifted: {e} Lift it with "
                    f"`boxmunge security resume {project}`."), False, True
        log_operation(_COMPONENT, f"{project}: quarantine lifted after autofix: {site}",
                      paths, project=project)
        return site, True, urgent
    # Taken for something else since: it stands, its containers stopped again.
    site = (f"The project stays quarantined for {record.get('cve_id')}, which this "
            f"patch was not for.")
    try:
        reassert_quarantine(project, paths, **_quarantine_kwargs(paths, project, job.meta))
    except QuarantineError as e:
        return f"{site} Re-asserting it failed: {e}.", False, True
    return site, True, False


def _lifted(restored: Restored) -> tuple[str, bool]:
    if restored.held is not None:
        return f"The quarantine is lifted, but the project stays down: {restored.held}.", False
    if restored.smoke is not None and not restored.smoke[0]:
        return (f"The quarantine is lifted and the site is back, but its smoke test "
                f"FAILED: {restored.smoke[1]}"), True
    return "The quarantine is lifted: the site is back online, smoke test OK.", False


def _fallback(paths: BoxPaths, project: str, job: _Job) -> tuple[str, bool]:
    """Table B: what the policy decided for the findings, applied now.
    (what that leaves the site as, whether it was applied)."""
    findings, meta, decisions = job.findings, job.meta, job.decisions
    dark = [fd for fd in findings if fd.disposition is Disposition.QUARANTINE]
    if not dark:
        if any(fd.disposition is Disposition.STILL_RUNNING_AT_RISK for fd in findings):
            return ("The site keeps running at risk: dangerously_disable_quarantine is "
                    "set, so it is not quarantined."), True
        return ("The site stays up; the scans keep alerting the findings until they are "
                "fixed."), True
    try:
        if read_quarantine_state(project, paths) is not None:
            reassert_quarantine(project, paths, **_quarantine_kwargs(paths, project, meta))
            return "The site stays quarantined: maintenance page up, containers stopped.", True
        if project in read_held(paths) and not any(fd.full_kev for fd in dark):
            return ("The circuit breaker holds this project's quarantine, so it keeps "
                    "running: apply it with `boxmunge security scan --apply-held`."), True
        head = dark[0]
        image_ref = next(d.image_ref for d in decisions if head in d.findings)
        quarantine_project(project, paths, **_quarantine_kwargs(paths, project, meta),
                           headline=head, exploited_by=quarantine_listing(decisions),
                           image_ref=image_ref, policy=meta.policy())
    except (QuarantineError, BreakerError) as e:
        log_error(_COMPONENT, f"{project}: quarantine after a failed autofix failed: {e}",
                  paths, project=project)
        return f"The quarantine could not be completed: {e}.", False
    return "The site is quarantined now: maintenance page up, containers stopped.", True
