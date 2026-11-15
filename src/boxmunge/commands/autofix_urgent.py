# SPDX-License-Identifier: Apache-2.0
"""The urgent autofix flow's run: patch what the scan queued, then apply the
outcome (CVE autofix flowcharts, chart 1 and table B).

The scan or KEV watch tick that queued a patch (commands.autofix_urgent_scan)
runs the queue at its end, under its fleet lock; both are root units, so
the patch builds run as root. For each queued project, under its project
lock (held by someone else: left for the next run, logged):

- the findings are read again from the project's stored scan, by the keys
  the queue holds: a queue entry is never trusted on its own. Gone (a later
  scan no longer finds them, or they stopped being urgent): the entry and
  the marker are dropped and nothing runs; a quarantine taken for them
  follows the scan's own lift rules;
- the deadline is the detection time plus AUTOFIX_URGENT_BUDGET. Passed
  already: nothing starts, and the fallback applies (failed step "budget");
- otherwise cve.autofix_run patches, swaps and health checks, by the
  deadline, and rolls back on any failure.

Success lifts the quarantine taken for the patch (the scan's lift path,
quarantine_lift.restore_from_quarantine), and one quiet notice says so: the
lift sends no alert of its own. Failure applies table B, which is the
policy's own disposition of the findings: one the policy takes down is
quarantined (re-asserted when it is already: the rollback started the
containers), one it leaves up or at risk stays so; then one urgent alert
names the step. Upgrade probation does not hold this back; only the
nightly flow waits for it.

A queue entry that cannot be read is alerted and skipped; the rest of the
queue still runs.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

from boxmunge.commands.quarantine_lift import Restored, restore_from_quarantine
from boxmunge.commands.security_enforce import quarantine_listing
from boxmunge.commands.security_scan_inputs import (
    ProjectMeta, ProjectScanError, load_project_meta,
)
from boxmunge.cve.alerting import (
    Alert, format_autofix_failed_alert, format_autofix_patched_alert, send_alerts,
)
from boxmunge.cve.autofix_policy import AUTOFIX_URGENT_BUDGET, AutofixUrgency, urgency
from boxmunge.cve.autofix_record import (
    QueueEntry, clear_autofixing, queued_projects, read_queue_entry, remove_queue_entry,
)
from boxmunge.cve.autofix_run import AutofixOutcome, autofix_project_locked
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
from boxmunge.state import StateError

_COMPONENT = "autofix"
_PROBLEMS = (StateError, ValueError, KeyError, TypeError, ManifestError, ProjectScanError,
             OSError)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def run_urgent_queue(paths: BoxPaths, now: datetime) -> list[AutofixOutcome]:
    """Run every queued urgent patch; the outcome of each that ran."""
    try:
        projects = queued_projects(paths)
    except StateError as e:
        _problem(paths, None, str(e))
        return []
    outcomes = []
    for project in projects:
        try:
            with project_lock(project, paths):
                outcome = _run_one(paths, project, max(now, _now()))
        except LockError:
            log_operation(_COMPONENT, f"{project}: queued autofix left for the next run: the "
                          f"project is held by another operation", paths, project=project)
            continue
        except InvalidProjectName as e:
            _problem(paths, None, f"the autofix queue holds {project!r}, not a project "
                     f"name: {e}")
            continue
        except _PROBLEMS as e:
            _problem(paths, project, f"{type(e).__name__}: {e}")
            continue
        if outcome is not None:
            print(f"{project}: autofix " + ("patched" if outcome.ok else
                  f"FAILED at {outcome.failed_step or 'an unexpected error'}: {outcome.reason}"))
            outcomes.append(outcome)
    return outcomes


def _problem(paths: BoxPaths, project: str | None, problem: str) -> None:
    """A queue entry or the state it needs is unusable: logged and alerted."""
    log_error(_COMPONENT, f"urgent autofix{f' of {project}' if project else ''} could not run: "
              f"{problem}", paths, project=project)
    title = f"[boxmunge:{project}]" if project else "[boxmunge]"
    _send(paths, Alert(kind="autofix_failed", priority=1,
                       title=f"{title} Urgent autofix could not run",
                       body="\n".join([
                           problem, "",
                           "Nothing was patched; what the scan decided stands. Fix or remove the",
                           f"entry under {paths.autofix_queue_dir}; the next scan queues the",
                           "patch again.",
                       ])))


def _send(paths: BoxPaths, alert: Alert) -> None:
    try:
        send_alerts((alert,), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block the flow
        log_warning(_COMPONENT, f"autofix alert delivery failed: {e}", paths)


def _stored(paths: BoxPaths, project: str) -> tuple[ProjectDecision, ...]:
    state = read_scan_state(paths.project_scan_state(project))
    if state is None:
        raise StateError(f"{project} has an autofix queued but no stored scan")
    return decisions_from_scan_state(state, project_name=project)


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


def _run_one(paths: BoxPaths, project: str, now: datetime) -> AutofixOutcome | None:
    entry = read_queue_entry(paths, project)
    if entry is None:
        return None
    meta = load_project_meta(paths, project)
    decisions = _stored(paths, project)
    findings = _current(decisions, entry, meta)
    if not findings:
        _done(paths, project)
        log_operation(_COMPONENT, f"{project}: queued autofix of {', '.join(entry.cves)} "
                      f"dropped: the stored scan no longer has them to patch", paths,
                      project=project)
        return None
    deadline = entry.detected_at + AUTOFIX_URGENT_BUDGET
    if not meta.autofix:
        outcome = AutofixOutcome(False, None, "autofix was turned off for this project "
                                 "before the patch started", ())
    elif now >= deadline:
        outcome = AutofixOutcome(False, "budget", f"the patch had not started by "
                                 f"{deadline.isoformat()}, {_minutes()} after detection", ())
    else:
        outcome = _patch(paths, project, findings, deadline)
    _done(paths, project)
    cves = sorted({fd.finding.cve_id for fd in findings})
    if outcome.ok:
        _send(paths, _succeeded(paths, project, meta, entry, cves, outcome))
    else:
        site = _fallback(paths, project, meta, decisions, findings)
        _send(paths, format_autofix_failed_alert(
            project, cves, step=outcome.failed_step, reason=outcome.reason, site=site,
            rollback_problems=outcome.rollback_problems))
    return outcome


def _minutes() -> str:
    return f"{int(AUTOFIX_URGENT_BUDGET.total_seconds() // 60)} minutes"


def _patch(paths: BoxPaths, project: str, findings: Sequence[FindingDisposition],
           deadline: datetime) -> AutofixOutcome:
    """The runner's outcome; an exception no step expects (rolled back, and
    logged by the runner) is a failure too, so the fallback still applies."""
    try:
        return autofix_project_locked(paths, project, findings, trigger="urgent",
                                      deadline=deadline)
    except Exception as e:  # noqa: BLE001 — the fallback must apply whatever failed
        notes = tuple(getattr(e, "__notes__", ()))
        return AutofixOutcome(False, None, f"{type(e).__name__}: {e}", (), notes)


def _quarantine_kwargs(paths: BoxPaths, project: str, meta: ProjectMeta) -> dict:
    return {"project_dir": paths.project_dir(project), "hosts": meta.hosts,
            "compose_files": meta.compose_files}


def _succeeded(paths: BoxPaths, project: str, meta: ProjectMeta, entry: QueueEntry,
               cves: Sequence[str], outcome: AutofixOutcome) -> Alert:
    """Lift the quarantine taken for the patch; the notice of what runs now."""
    urgent = False
    try:
        record = read_quarantine_state(project, paths)
    except QuarantineError as e:
        return format_autofix_patched_alert(project, cves, outcome.records, urgent=True, site=(
            f"Whether the project is quarantined cannot be read: {e}"))
    if record is None:
        site = "The site stayed up while it was patched."
    elif record.get("cve_id") in entry.cves:
        try:
            site, urgent = _lifted(restore_from_quarantine(paths, project,
                                                           component=_COMPONENT))
        except QuarantineError as e:
            site, urgent = (f"The quarantine could not be lifted: {e} Lift it with "
                            f"`boxmunge security resume {project}`."), True
        log_operation(_COMPONENT, f"{project}: quarantine lifted after autofix: {site}",
                      paths, project=project)
    else:   # taken for something else since: it stands, containers stopped again
        site = (f"The project stays quarantined for {record.get('cve_id')}, which this "
                f"patch was not for.")
        try:
            reassert_quarantine(project, paths, **_quarantine_kwargs(paths, project, meta))
        except QuarantineError as e:
            site, urgent = f"{site} Re-asserting it failed: {e}; the next scan retries.", True
    return format_autofix_patched_alert(project, cves, outcome.records, site=site,
                                        urgent=urgent)


def _lifted(restored: Restored) -> tuple[str, bool]:
    if restored.held is not None:
        return f"The quarantine is lifted, but the project stays down: {restored.held}.", False
    if restored.smoke is not None and not restored.smoke[0]:
        return (f"The quarantine is lifted and the site is back, but its smoke test "
                f"FAILED: {restored.smoke[1]}"), True
    return "The quarantine is lifted: the site is back online, smoke test OK.", False


def _fallback(paths: BoxPaths, project: str, meta: ProjectMeta,
              decisions: Sequence[ProjectDecision],
              findings: Sequence[FindingDisposition]) -> str:
    """Table B: what the policy decided for the findings, applied now.
    Returns what that leaves the site as, for the alert."""
    dark = [fd for fd in findings if fd.disposition is Disposition.QUARANTINE]
    if not dark:
        if any(fd.disposition is Disposition.STILL_RUNNING_AT_RISK for fd in findings):
            return ("The site keeps running at risk: dangerously_disable_quarantine is "
                    "set, so it is not quarantined.")
        return "The site stays up; the scans keep alerting the findings until they are fixed."
    try:
        if read_quarantine_state(project, paths) is not None:
            reassert_quarantine(project, paths, **_quarantine_kwargs(paths, project, meta))
            return "The site stays quarantined: maintenance page up, containers stopped."
        if project in read_held(paths) and not any(fd.full_kev for fd in dark):
            return ("The circuit breaker holds this project's quarantine, so it keeps "
                    "running: apply it with `boxmunge security scan --apply-held`.")
        head = dark[0]
        image_ref = next(d.image_ref for d in decisions if head in d.findings)
        quarantine_project(project, paths, **_quarantine_kwargs(paths, project, meta),
                           headline=head, exploited_by=quarantine_listing(decisions),
                           image_ref=image_ref, policy=meta.policy())
    except (QuarantineError, BreakerError) as e:
        log_error(_COMPONENT, f"{project}: quarantine after a failed autofix failed: {e}",
                  paths, project=project)
        return f"The quarantine could not be completed: {e}; the next scan retries it."
    return "The site is quarantined now: maintenance page up, containers stopped."
