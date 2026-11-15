# SPDX-License-Identifier: Apache-2.0
"""The nightly autofix flow: patch, in the maintenance window, the fixable
findings that are not known exploited (CVE autofix design, "Non-KEV flow").

The maintenance unit runs the fleet scan, then container-update. After each
user project's own container update, under the same project lock
(container_update_cmd.update_project), the project's findings are read from
the scan it just stored, and those `cve.autofix_policy.urgency` calls
NIGHTLY (on the patch path, at or above what the posture alerts on,
balanced's threshold under relaxed, not suppressed, not listed) are patched
by cve.autofix_run, with the site up, by a deadline AUTOFIX_NIGHTLY_BUDGET
after this attempt's own start. The runner scans the running images again
first, so a project the container update just moved onto a new upstream
image is patched on that image, or told there is nothing left to patch.

Nothing runs when the update did not leave the project running as before
(quarantined, paused, migrating, stopped by the health monitor, busy, or a
failed update: the next night tries again); during upgrade probation, even
on a forced container-update; when the project has `security.autofix` off;
or when an urgent patch is queued for it or an interrupted run left its
journal: the autofix unit (commands.autofix_urgent) owns those. Each skip
that could hide a patch is logged.

The outcomes go out as ONE quiet digest from container-update (priority -1):
"patched: <project>: <CVEs> (<n> packages)" or "could not patch: <project>:
<step>: <reason>". A failure whose rollback did not finish may leave the
project mixed: it is the urgent failure alert, at once, never quiet.
"""
from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.commands.security_scan_inputs import ProjectScanError, load_project_meta
from boxmunge.cve.alerting import (
    Alert, format_autofix_digest, format_autofix_failed_alert, format_nightly_failed_line,
    format_nightly_patched_line, send_alerts,
)
from boxmunge.cve.autofix_policy import AUTOFIX_NIGHTLY_BUDGET, AutofixUrgency, urgency
from boxmunge.cve.autofix_run import AutofixOutcome, autofix_project_locked
from boxmunge.cve.policy import FindingDisposition
from boxmunge.cve.scan_state import decisions_from_scan_state, read_scan_state
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.manifest import ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

_COMPONENT = "autofix"
_READ_PROBLEMS = (StateError, ValueError, KeyError, TypeError, ManifestError,
                  ProjectScanError, OSError)
# The container update statuses that leave a project running as it was, or
# on images the update put through its gates.
_UPDATED = frozenset({"succeeded", "no_change"})


@dataclass(frozen=True)
class NightlyAttempt:
    """One project's nightly patch: the CVEs it was for, and its outcome."""
    project: str
    cves: tuple[str, ...]
    outcome: AutofixOutcome


def _now() -> datetime:
    return datetime.now(timezone.utc)


def after_update(paths: BoxPaths, project: str,
                 result: dict[str, Any]) -> NightlyAttempt | None:
    """Container-update's hook, under the project lock it updated under."""
    if result["status"] == "failed":
        log_operation(_COMPONENT, f"{project}: nightly autofix skipped: tonight's container "
                      f"update failed ({result.get('reason')}); the next night tries again",
                      paths, project=project)
        return None
    if result["status"] not in _UPDATED:   # the update logged why it skipped
        return None
    return run_nightly_autofix(paths, project)


def run_nightly_autofix(paths: BoxPaths, project: str) -> NightlyAttempt | None:
    """Patch the project's nightly findings; None when there is nothing to
    run. The caller holds the project lock (the runner checks)."""
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
    cves = tuple(sorted({fd.finding.cve_id for fd in findings}))
    started = _now()
    try:
        outcome = autofix_project_locked(paths, project, findings, trigger="nightly",
                                         deadline=started + AUTOFIX_NIGHTLY_BUDGET)
    except Exception as e:  # noqa: BLE001 — rolled back and logged by the runner
        outcome = AutofixOutcome(False, None, f"{type(e).__name__}: {e}", (),
                                 tuple(getattr(e, "__notes__", ())))
    print(f"{project}: nightly autofix " + ("patched" if outcome.ok else
          f"FAILED at {outcome.failed_step or 'an unexpected error'}: {outcome.reason}"))
    return NightlyAttempt(project, cves, replace(outcome, started_at=started))


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
        if o.ok:
            quiet.append(format_nightly_patched_line(a.project, a.cves, o.records))
        elif o.rollback_problems:
            loud.append(_mixed_alert(a))
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


def _mixed_alert(a: NightlyAttempt) -> Alert:
    o = a.outcome
    started = o.started_at or _now()
    timing = f"Nightly patch started {started:%H:%M} UTC, failed {_now():%H:%M} UTC."
    return format_autofix_failed_alert(
        a.project, a.cves, step=o.failed_step, reason=o.reason,
        site="The site was not quarantined: nightly patches are for findings that keep it up.",
        timing=timing, rollback_problems=o.rollback_problems)
