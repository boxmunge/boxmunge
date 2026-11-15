# SPDX-License-Identifier: Apache-2.0
"""The scan's half of the urgent autofix flow: decide, mark and queue.

A scan (the nightly one, or the KEV watch's rescan) that finds an URGENT
finding (cve.autofix_policy.urgency) on a project with `security.autofix`
on queues it here, under the project lock, before enforcement:

- downtime (flowchart table A, or the project is quarantined already):
  the quarantine is taken the normal way. The circuit breaker still weighs
  a finding that is not full KEV; one it holds is patched with the site up
  (held_for_patch records that after the fleet run's phase 2);
- otherwise the site stays up: the quarantine its findings would take is
  held back while it is patched, and the autofixing marker says so.

Either way the marker holds {cves, downtime} and the queue entry holds the
findings and their detection time. One alert says patching started: the
QUARANTINED alert itself when the scan quarantines the project for the
patch, the autofix_started notice otherwise (the site stays up, or it was
quarantined already). The patch runs once the scan is over
(commands.autofix_queue_cmd, commands.autofix_urgent).

A scan that finds the findings queued already keeps the entry's detection
time, adding any new finding to it. An entry still waiting
AUTOFIX_QUEUE_MAX_WAIT after its detection is stuck (the autofix unit does
not start, or another operation keeps holding the project): the scan stops
holding the quarantine back (table B: the project is quarantined when the
policy takes it down, and the patch, still queued, then runs dark), and
alerts it at most once a day; the `autofix-queue` health check warns.

Nothing is queued when autofix cannot help: it is off, the project is down
on purpose (paused, stopped by the health monitor), something else keeps it
down, the image cannot be patched (cve.autofix_build.probe), or the same
patch failed before and nothing it depends on has changed
(cve.autofix_failed). Today's disposition then stands, and the reason is
added to the alerts that name the findings (the QUARANTINED alert
included), not sent as one more alert.
"""
from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from boxmunge.commands.quarantine_lift import start_hold
from boxmunge.commands.security_scan_inputs import ProjectMeta
from boxmunge.compose_images import image_phrase
from boxmunge.cve.alerting import Alert, format_autofix_started_alert
from boxmunge.cve.autofix_build import NotPatchable, probe
from boxmunge.cve.autofix_failed import forget, still_failing, unpatched
from boxmunge.cve.autofix_policy import (
    AUTOFIX_QUEUE_MAX_WAIT, AutofixUrgency, downtime_while_patching, urgency,
)
from boxmunge.cve.autofix_record import (
    QueuedFinding, QueueEntry, clear_autofixing, mark_autofixing, read_queue_entry,
    remove_queue_entry, write_queue_entry,
)
from boxmunge.cve.breaker import BreakerError, read_held
from boxmunge.cve.policy import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.quarantine import QuarantineError, is_quarantined, read_quarantine_state
from boxmunge.docker_run import DockerError
from boxmunge.log import log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.project_alerts import alert_once
from boxmunge.state import StateError

_COMPONENT = "autofix"

Urgent = tuple[ProjectDecision, FindingDisposition]


@dataclass(frozen=True)
class UrgentPlan:
    """What the scan does about its urgent findings (``cves``). ``queued``:
    they are patched at the end of the run, with the project down for it
    when ``downtime``. ``note``: why autofix cannot help, for the alerts."""
    cves: tuple[str, ...] = ()
    queued: bool = False
    downtime: bool = False
    note: str | None = None

    @property
    def quarantine_note(self) -> str | None:
        """What the QUARANTINED alert adds: why autofix cannot help, or that
        the quarantine is for the patch now running."""
        if self.queued and self.downtime:
            return PATCHING_NOTE
        return self.note

    def headline(self, headline: Urgent | None) -> Urgent | None:
        """The quarantine headline enforcement gets: none while the site stays
        up for its patch (nothing else quarantines it: see ``_blocker``)."""
        return None if self.queued and not self.downtime else headline

    def annotate(self, alerts: list[Alert], start: int = 0) -> None:
        """Add the note to each alert from ``start`` on that names a CVE."""
        if self.note is None:
            return
        for i in range(start, len(alerts)):
            if any(cve in alerts[i].body for cve in self.cves):
                alerts[i] = with_note(alerts[i], self.note)


NOTHING_URGENT = UrgentPlan()
PATCHING_NOTE = ("Autofix is patching it now; the site comes back automatically if the "
                 "patch passes.")


def with_note(alert: Alert, note: str | None) -> Alert:
    return alert if note is None else replace(alert, body=f"{alert.body}\n\n{note}")


def prepare_urgent(paths: BoxPaths, project: str, meta: ProjectMeta,
                   decisions: Sequence[ProjectDecision], *, now: datetime,
                   alerts: list[Alert]) -> UrgentPlan:
    """Queue the project's urgent findings, or say why autofix cannot help.
    The caller holds the project lock. Appends the started notice to
    ``alerts`` when it queues something new."""
    urgent = [(d, fd) for d in decisions for fd in d.findings
              if urgency(fd, meta.posture) is AutofixUrgency.URGENT]
    if not urgent:
        forget(paths, project, "urgent")
        return NOTHING_URGENT
    cves = tuple(sorted({fd.finding.cve_id for _, fd in urgent}))
    try:
        blocker = _blocker(paths, project, meta, decisions, urgent, cves)
        existing = None if blocker else read_queue_entry(paths, project)
        downtime = None if blocker else _downtime(paths, project, meta, urgent)
    except (StateError, QuarantineError, BreakerError) as e:
        blocker = f"what it may patch cannot be read ({e})"
        existing, downtime = None, None
    if blocker is None and existing is None:
        failed = still_failing(paths, project, "urgent", urgent)
        if failed is not None:
            blocker = (f"the same patch failed and nothing it depends on has changed, "
                       f"{unpatched(failed)}; it is tried again when the image or the fix "
                       f"changes")
    if blocker is not None:
        log_warning(_COMPONENT, f"{project}: autofix cannot help with {', '.join(cves)}: "
                    f"{blocker}", paths, project=project, detail={"cves": list(cves)})
        _forget(paths, project)
        return UrgentPlan(cves, note=f"Autofix cannot help: {blocker}.")
    assert downtime is not None
    if existing is not None and now - existing.detected_at >= AUTOFIX_QUEUE_MAX_WAIT:
        stuck(paths, project, existing, reason=None)
        downtime = downtime or any(fd.disposition is Disposition.QUARANTINE
                                   for _, fd in urgent)
    keys = {_key(d, fd) for d, fd in urgent}
    if existing is not None and keys <= set(existing.findings):
        if existing.downtime is not downtime:
            try:
                record_downtime(paths, project, existing, downtime=downtime)
            except StateError as e:
                log_warning(_COMPONENT, f"{project}: {e}", paths, project=project)
                downtime = existing.downtime
        return UrgentPlan(existing.cves, queued=True, downtime=downtime)
    quarantined = is_quarantined(project, paths)
    try:
        queue_urgent(paths, project, downtime=downtime, now=now, keys=keys, existing=existing)
    except StateError as e:
        log_warning(_COMPONENT, f"{project}: autofix of {', '.join(cves)} not queued: {e}",
                    paths, project=project)
        return UrgentPlan(cves, note=f"Autofix cannot help: it could not be queued ({e}).")
    if not downtime or quarantined:   # else the QUARANTINED alert says it (quarantine_note)
        alerts.append(format_autofix_started_alert(project, cves, downtime=downtime))
    return UrgentPlan(cves, queued=True, downtime=downtime)


def _downtime(paths: BoxPaths, project: str, meta: ProjectMeta,
              urgent: Sequence[Urgent]) -> bool:
    """Whether the project is down while it is patched: it is quarantined
    already, or table A says dark and it can be (not opted out, and not held
    by the circuit breaker, which never holds a full-KEV one). Raises
    BreakerError."""
    if is_quarantined(project, paths):
        return True
    if meta.dangerously or not any(downtime_while_patching(fd, meta.posture)
                                   for _, fd in urgent):
        return False
    return not (project in read_held(paths) and not any(fd.full_kev for _, fd in urgent))


def record_downtime(paths: BoxPaths, project: str, entry: QueueEntry, *,
                    downtime: bool) -> None:
    """Rewrite a queued patch (and its marker) with whether the project is
    down for it, keeping its detection time. Raises StateError."""
    mark_autofixing(paths, project, entry.cves, downtime=downtime)
    write_queue_entry(paths, project, replace(entry, downtime=downtime))


def held_for_patch(paths: BoxPaths, held: Collection[str]) -> list[Alert]:
    """The projects whose quarantine for a patch the circuit breaker held
    this run stay up while they are patched: record that, and the started
    notice for each (no QUARANTINED alert said it)."""
    notices = []
    for project in sorted(held):
        try:
            entry = read_queue_entry(paths, project)
            if entry is None or not entry.downtime or is_quarantined(project, paths):
                continue
            record_downtime(paths, project, entry, downtime=False)
        except StateError as e:
            log_warning(_COMPONENT, f"{project}: {e}", paths, project=project)
            continue
        notices.append(format_autofix_started_alert(project, entry.cves, downtime=False))
    return notices


def queue_urgent(paths: BoxPaths, project: str, *, downtime: bool, now: datetime,
                 keys: Collection[QueuedFinding], existing: QueueEntry | None) -> None:
    """Mark the project autofixing and queue ``keys`` (the findings, by
    image), detected ``now``, with those of the ``existing`` entry and its
    detection time when there is one. Raises StateError."""
    merged = sorted({*keys, *(existing.findings if existing else ())},
                    key=lambda k: (k.cve_id, k.package, k.image_ref))
    entry = QueueEntry(existing.detected_at if existing else now, now, tuple(merged), downtime)
    cves = list(entry.cves)
    mark_autofixing(paths, project, cves, downtime=downtime)
    write_queue_entry(paths, project, entry)
    log_operation(_COMPONENT, f"{project}: {', '.join(cves)} queued for urgent autofix, "
                  f"{'site down' if downtime else 'site up'} while patching", paths,
                  project=project, detail={"cves": cves, "downtime": downtime})


def stuck(paths: BoxPaths, project: str, entry: QueueEntry, *, reason: str | None) -> None:
    """The entry has waited AUTOFIX_QUEUE_MAX_WAIT: logged, alerted at most
    once a day (``reason``: why, when the caller knows)."""
    hours = AUTOFIX_QUEUE_MAX_WAIT.total_seconds() / 3600
    why = reason or ("the autofix unit has not run it; see `journalctl -u boxmunge-autofix` "
                     "and `boxmunge log --component autofix`")
    day = datetime.now(timezone.utc).date().isoformat()
    alert_once(paths, project, "autofix-stuck", {"day": day},
               title=f"[boxmunge:{project}] Urgent autofix could not start", priority=1,
               component=_COMPONENT, message="\n".join([
                   f"Autofix could not start for {hours:g}h: {why}.",
                   f"The patch of {', '.join(entry.cves)} (found "
                   f"{entry.detected_at:%Y-%m-%d %H:%M} UTC) stays queued. The scans no longer",
                   "hold its quarantine back: the project is quarantined where the posture",
                   "takes it down for these findings. Alerted once a day while it lasts.",
               ]))


def _key(decision: ProjectDecision, fd: FindingDisposition) -> QueuedFinding:
    return QueuedFinding(fd.finding.cve_id, fd.finding.package, decision.image_ref)


def _forget(paths: BoxPaths, project: str) -> None:
    """Drop a queued patch autofix can no longer run. Logged, never raised:
    the runner re-checks what it finds anyway."""
    try:
        remove_queue_entry(paths, project)
        clear_autofixing(paths, project)
    except StateError as e:
        log_warning(_COMPONENT, f"{project}: {e}", paths, project=project)


def _blocker(paths: BoxPaths, project: str, meta: ProjectMeta,
             decisions: Sequence[ProjectDecision], urgent: Sequence[Urgent],
             cves: tuple[str, ...]) -> str | None:
    """Why autofix cannot patch the urgent findings now, or None."""
    if not meta.autofix:
        return "autofix is off for this project (security.autofix: false)"
    held = start_hold(paths, project)
    if held is not None:
        return f"autofix does not start a project that is down on purpose: {held}"
    for d in decisions:
        for fd in d.findings:
            if fd.disposition is Disposition.QUARANTINE and urgency(
                    fd, meta.posture) is not AutofixUrgency.URGENT:
                return (f"{fd.finding.cve_id} in {fd.finding.package} also takes the site "
                        f"down, and autofix cannot patch it")
    record = read_quarantine_state(project, paths)
    if record is not None and record.get("cve_id") not in cves:
        return (f"the project is quarantined for {record.get('cve_id')}, which autofix "
                f"does not patch")
    for ref in sorted({d.image_ref for d, _ in urgent}):
        try:
            found = probe(ref)
        except DockerError as e:
            return f"probing {image_phrase(ref)} failed: {e}"
        if isinstance(found, NotPatchable):
            return f"{image_phrase(ref)} cannot be patched: {found.reason}"
    return None
