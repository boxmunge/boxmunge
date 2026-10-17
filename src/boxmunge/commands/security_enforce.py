# SPDX-License-Identifier: Apache-2.0
"""Quarantine enforcement: take, re-assert, and announce the action.

Deciding (security_scan_core) is kept apart from acting (here). The
QUARANTINED alert is tied to the action, not to a change in a finding's
disposition (audit B-17): it fires when a quarantine actually lands, so
the first enforcing scan after the migration grace window — whose
dispositions were already QUARANTINE while in grace — still tells the
operator the site went dark.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from boxmunge.cve.alerting import findings_by_key, format_quarantine_alert, send_alerts
from boxmunge.cve.policy import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.quarantine import (
    QuarantineError,
    is_quarantined,
    quarantine_action_complete,
    quarantine_project,
    read_quarantine_state,
    reassert_quarantine,
)
from boxmunge.legacy_stage import cannot_tell, legacy_stage
from boxmunge.log import log_warning
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths


@dataclass(frozen=True)
class Enforcement:
    """Outcome of one enforcement attempt for one project."""

    error: str | None = None
    # The quarantine landed on this attempt: a new one, or an earlier
    # partial one completed. The QUARANTINED alert is due.
    landed: bool = False
    # The CVE that would have quarantined the project, held because a
    # 0.10.1 stage is in place (spec "On the beta, until it is resolved").
    held: str | None = None


def enforce(
    paths: BoxPaths, project: str, *,
    hosts: list[str], compose_files: list[str],
    headline: tuple[ProjectDecision, FindingDisposition] | None,
    in_grace: bool,
) -> Enforcement:
    """Take or re-assert the quarantine action for ``project``.

    An existing record is re-asserted whatever this scan found, so a
    partially failed action converges (audit B-03). During grace no NEW
    quarantine fires; the heads-up alert summarises what would. For a
    project with a 0.10.1 stage both are held (Enforcement.held); when it
    cannot be told whether one is on disk, a due action is not taken and
    is reported as the error.
    """
    project_dir = paths.project_dir(project)
    try:
        try:
            legacy = legacy_stage(paths, project) is not None
        except OSError as e:
            return _undetermined(paths, project, e, due=headline is not None and not in_grace)
        if is_quarantined(project, paths):
            if legacy:
                # Re-asserting stops the containers again: production's.
                return _hold(paths, project, _recorded_cve(project, paths), reasserting=True)
            was_complete = quarantine_action_complete(project, paths)
            reassert_quarantine(
                project, paths, project_dir=project_dir,
                hosts=hosts, compose_files=compose_files,
            )
            return Enforcement(landed=not was_complete)
        if headline is not None and not in_grace:
            if legacy:
                return _hold(paths, project, headline[1].finding.cve_id, reasserting=False)
            quarantine_project(
                project, paths, project_dir=project_dir,
                hosts=hosts, compose_files=compose_files,
                headline=headline[1], image_ref=headline[0].image_ref,
            )
            return Enforcement(landed=True)
    except QuarantineError as e:
        return Enforcement(error=f"quarantine action failed for {project!r}: {e}")
    return Enforcement()


def _undetermined(paths: BoxPaths, project: str, error: OSError, *, due: bool) -> Enforcement:
    """A 0.10.1 stage may be on disk: acting could stop production, so a due
    action (a new quarantine, or re-asserting a recorded one) is not taken
    and is reported. A record that cannot be read either is reported too."""
    not_taken = f"quarantine action not taken: {cannot_tell(project, error)}"
    try:
        due = due or is_quarantined(project, paths)
    except OSError as e:
        return Enforcement(error=f"{not_taken}; its quarantine record cannot be read either: {e}")
    return Enforcement(error=not_taken if due else None)


def _recorded_cve(project: str, paths: BoxPaths) -> str:
    cve = (read_quarantine_state(project, paths) or {}).get("cve_id")
    if not isinstance(cve, str) or not cve:
        raise QuarantineError(f"the quarantine record of {project!r} names no cve_id")
    return cve


def _hold(paths: BoxPaths, project: str, cve: str, *, reasserting: bool) -> Enforcement:
    """Hold, not take or re-assert, the quarantine of a project with a 0.10.1
    stage: it would stop production, and security resume and legacy-stage
    stay refused until probation ends."""
    action = ("its quarantine for {cve} would be re-asserted" if reasserting
              else "it would be quarantined for {cve}").format(cve=cve)
    message = (f"{project}: {action}, but it has a release staged by boxmunge 0.10.1: "
               f"a quarantine would stop production, and security resume and "
               f"legacy-stage stay refused until probation ends. Resolve it with "
               f"`boxmunge-server legacy-stage {project}`.")
    log_warning("cve-scan", message, paths, project=project, detail={"cve": cve})
    notify(paths, f"{project}: quarantine held", message,
           component="cve-scan", project=project, priority=1)
    return Enforcement(held=cve)


def announce_quarantine(
    paths: BoxPaths, project: str, decisions: Sequence[ProjectDecision],
) -> None:
    """Send the QUARANTINED alert listing every quarantine-level finding.

    Best-effort: a delivery failure is logged, never raised.
    """
    hits = [
        hit for hit in findings_by_key(decisions).values()
        if hit.disposition.disposition == Disposition.QUARANTINE
    ]
    if not hits:
        return
    try:
        send_alerts((format_quarantine_alert(project, hits),), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning(
            "cve-scan", f"quarantine alert emission failed for {project}: {e}",
            paths, project=project, detail={"error": str(e)},
        )


def headline_of(
    decisions: Sequence[ProjectDecision],
) -> tuple[ProjectDecision, FindingDisposition] | None:
    """The first QUARANTINE finding (findings are sorted most-severe first)."""
    for decision in decisions:
        for disp in decision.findings:
            if disp.disposition == Disposition.QUARANTINE:
                return decision, disp
    return None


def raise_enforcement_error(error: str | None) -> None:
    """Fail the project scan loudly once its state has been persisted."""
    if error is not None:
        raise RuntimeError(f"{error} (the next scan retries it)")
