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
    reassert_quarantine,
)
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths


@dataclass(frozen=True)
class Enforcement:
    """Outcome of one enforcement attempt for one project."""

    error: str | None = None
    # The quarantine landed on this attempt: a new one, or an earlier
    # partial one completed. The QUARANTINED alert is due.
    landed: bool = False


def enforce(
    paths: BoxPaths, project: str, *,
    hosts: list[str], compose_files: list[str],
    headline: tuple[ProjectDecision, FindingDisposition] | None,
    in_grace: bool,
) -> Enforcement:
    """Take or re-assert the quarantine action for ``project``.

    An existing record is re-asserted whatever this scan found, so a
    partially failed action converges (audit B-03). During grace no NEW
    quarantine fires; the heads-up alert summarises what would.
    """
    project_dir = paths.project_dir(project)
    try:
        if is_quarantined(project, paths):
            was_complete = quarantine_action_complete(project, paths)
            reassert_quarantine(
                project, paths, project_dir=project_dir,
                hosts=hosts, compose_files=compose_files,
            )
            return Enforcement(landed=not was_complete)
        if headline is not None and not in_grace:
            quarantine_project(
                project, paths, project_dir=project_dir,
                hosts=hosts, compose_files=compose_files,
                headline=headline[1], image_ref=headline[0].image_ref,
            )
            return Enforcement(landed=True)
    except QuarantineError as e:
        return Enforcement(error=f"quarantine action failed for {project!r}: {e}")
    return Enforcement()


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


def raise_enforcement_error(error: str | None) -> None:
    """Fail the project scan loudly once its state has been persisted."""
    if error is not None:
        raise RuntimeError(f"{error} (the next scan retries it)")
