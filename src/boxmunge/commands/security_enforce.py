# SPDX-License-Identifier: Apache-2.0
"""Quarantine enforcement: take, re-assert, and announce the action.

Deciding (security_scan_core) is kept apart from acting (here). The
QUARANTINED alert is tied to the action, not to a change in a finding's
disposition (audit B-17): it fires when a quarantine actually lands, so
a quarantine the fleet run applies after deferring it, or one that
converges on a later scan, still tells the operator the site went dark.

A quarantine of a `balanced` project lifts on its own when a scan covered
every image the project starts, against a fresh KEV catalog, and found no
quarantine-level and no KEV-listed finding: balanced takes a site down only
for active exploitation (from 0.11.2), so a quarantine the earlier
severity rule took no longer stands. It is announced once, naming why.
Every other posture keeps deploy or `security resume` as the way out: a
published fix not yet deployed, or a distro re-triage, is not evidence the
running images are safe. A stale KEV catalog never lifts one: it reads as
"nothing exploited", which is exactly what must not be trusted. Nor does a
lift start a paused project or one the health monitor stopped: its quarantine
is lifted and it stays down (quarantine_lift.start_hold, the rule `security
resume` follows too) until `resume` or `recover`.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from boxmunge.commands.kev_withdrawal import withdrawal_hold
from boxmunge.commands.quarantine_lift import restore_from_quarantine
from boxmunge.cve.alerting import (
    findings_by_key, format_quarantine_alert, format_quarantine_lifted_alert, lift_reason,
    send_alerts,
)
from boxmunge.cve.exploited import ExploitedSource
from boxmunge.cve.lift_rule import stale_listers
from boxmunge.cve.policy_types import listing_label
from boxmunge.cve.policy import Disposition, FindingDisposition, Posture, ProjectDecision
from boxmunge.cve.quarantine import (
    QuarantineError,
    checked_quarantine_record,
    is_quarantined,
    quarantine_action_complete,
    quarantine_project,
    read_quarantine_state,
    reassert_quarantine,
    recorded_exploited_by,
)
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_warning
from boxmunge.paths import BoxPaths


@dataclass(frozen=True)
class Enforcement:
    """Outcome of one enforcement attempt for one project."""

    error: str | None = None
    # The quarantine landed on this attempt: a new one, or an earlier
    # partial one completed. The QUARANTINED alert is due.
    landed: bool = False
    # The CVE whose quarantine this attempt lifted: the scan cleared it.
    lifted: str | None = None
    # Why a quarantine the scan cleared was kept (re-asserted) instead.
    kept: str | None = None


def enforce(
    paths: BoxPaths, project: str, *,
    hosts: list[str], compose_files: list[str], policy: dict[str, Any],
    headline: tuple[ProjectDecision, FindingDisposition] | None,
    exploited_by: Mapping[str, frozenset[ExploitedSource]],
    defer_new: bool,
    cleared: Sequence[ProjectDecision] | None = None,
    stale_sources: Mapping[ExploitedSource, str] | None = None,
) -> Enforcement:
    """Take, re-assert or lift the quarantine action for ``project``.

    ``cleared`` is this scan's decisions when they clear the quarantine
    (``clears_quarantine``), with ``stale_sources`` the known-exploited
    sources that cannot be trusted now (required then); an existing
    quarantine is lifted, unless a source that listed it is stale
    (``listing_hold``), ``_lift_blocker`` says it must not be, or a KEV refresh withdrew its
    CVE and the images still contain it (kev_withdrawal). Otherwise an
    existing record is re-asserted, so a partially failed action converges
    (audit B-03). With ``defer_new`` no NEW quarantine fires here: the fleet
    run weighs it through the circuit breaker.
    """
    project_dir = paths.project_dir(project)
    try:
        if is_quarantined(project, paths):
            blocker = None
            if cleared is not None:
                if stale_sources is None:
                    raise ValueError("a clearing scan must say which sources are stale")
                blocker = (listing_hold(paths, project, stale_sources)
                           or withdrawal_hold(paths, project, cleared)
                           or _lift_blocker(paths, project))
            if cleared is not None and blocker is None:
                return _lift_cleared(paths, project, cleared)
            was_complete = quarantine_action_complete(project, paths)
            reassert_quarantine(
                project, paths, project_dir=project_dir,
                hosts=hosts, compose_files=compose_files,
            )
            if blocker is not None:
                log_warning("cve-scan", f"{project}: {blocker}", paths, project=project)
            return Enforcement(landed=not was_complete, kept=blocker)
        if headline is not None and not defer_new:
            quarantine_project(
                project, paths, project_dir=project_dir,
                hosts=hosts, compose_files=compose_files,
                headline=headline[1], exploited_by=exploited_by,
                image_ref=headline[0].image_ref, policy=policy,
            )
            return Enforcement(landed=True)
    except QuarantineError as e:
        return Enforcement(error=f"quarantine action failed for {project!r}: {e}")
    return Enforcement()


def clears_quarantine(posture: Posture, decisions: Sequence[ProjectDecision], *,
                      complete: bool, kev_fresh: bool) -> bool:
    """Whether a scan's ``decisions`` lift the project's quarantine on their
    own: a balanced project, scanned completely against a fresh KEV catalog,
    with no quarantine-level and no KEV-listed finding (see the module
    docstring for why only balanced)."""
    findings = [f for d in decisions for f in d.findings]
    return (posture is Posture.BALANCED and complete and kev_fresh
            and not any(f.full_kev or f.disposition is Disposition.QUARANTINE
                        for f in findings))


def quarantine_listing(
    decisions: Sequence[ProjectDecision],
) -> dict[str, frozenset[ExploitedSource]]:
    """The known-exploited sources listing each quarantine-level CVE."""
    out: dict[str, frozenset[ExploitedSource]] = {}
    for d in decisions:
        for f in d.findings:
            if f.disposition is Disposition.QUARANTINE and f.exploited_by:
                out[f.finding.cve_id] = out.get(f.finding.cve_id, frozenset()) | f.exploited_by
    return out


def listing_hold(paths: BoxPaths, project: str,
                 stale_sources: Mapping[ExploitedSource, str]) -> str | None:
    """Why a cleared quarantine is kept because a source that listed it is
    stale (it reads as "nothing is exploited"), or None. Like a stale CISA
    catalog, an unattended lift takes only the fresh case (``clears_quarantine``
    judges CISA itself); `security resume` judges the CVEs still present."""
    record = checked_quarantine_record(read_quarantine_state(project, paths),
                                       paths.project_quarantine_state(project))
    stale_by = stale_listers(recorded_exploited_by(record), stale_sources)
    if not stale_by:
        return None
    named = "; ".join(f"the {listing_label(frozenset({s}))} list is stale ({stale_sources[s]})"
                      for s in stale_by)
    return (f"quarantine kept: {named}, and it listed this quarantine's findings; "
            f"refresh it with `boxmunge security scan`, or judge the risk with "
            f"`boxmunge security resume {project} --accept-stale-kev`")


def _lift_blocker(paths: BoxPaths, project: str) -> str | None:
    """Why a cleared quarantine must not be lifted from here, or None. A
    project mid-migration is not lifted (security resume refuses it too):
    its quarantine is re-asserted instead, and the scan says so. Whether the
    lift may start the project is quarantine_lift's (start_hold)."""
    block = is_blocked(project, paths)
    if block is not None and block.reason is BlockReason.MIGRATING:
        return "quarantine kept: a userns migration is in progress; the scan after it lifts it"
    return None


def _lift_cleared(
    paths: BoxPaths, project: str, decisions: Sequence[ProjectDecision],
) -> Enforcement:
    """Lift the quarantine a clear scan no longer supports; announce it once."""
    cve = _recorded_cve(project, paths)
    try:
        restored = restore_from_quarantine(paths, project, component="cve-scan")
    except QuarantineError as e:
        return Enforcement(error=f"automatic quarantine lift failed for {project!r}: {e}")
    hits = [h for (c, _pkg), h in findings_by_key(decisions).items() if c == cve]
    reason = lift_reason(cve, hits)
    log_operation("cve-scan", f"{project}: quarantine for {cve} lifted by the scan: {reason}",
                  paths, project=project, detail={"cve": cve})
    alert = format_quarantine_lifted_alert(
        project, cve, reason, held=restored.held, smoke=restored.smoke)
    try:
        send_alerts((alert,), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning("cve-scan", f"quarantine-lifted alert emission failed for {project}: {e}",
                    paths, project=project, detail={"error": str(e)})
    return Enforcement(lifted=cve)


def _recorded_cve(project: str, paths: BoxPaths) -> str:
    cve = (read_quarantine_state(project, paths) or {}).get("cve_id")
    if not isinstance(cve, str) or not cve:
        raise QuarantineError(f"the quarantine record of {project!r} names no cve_id")
    return cve


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


def raise_enforcement_error(error: str | None, record_error: str | None = None) -> None:
    """Fail the project scan loudly once its state has been persisted (or
    failed to be: that error is carried along, never hiding this one)."""
    if error is not None:
        also = f"; also: {record_error}" if record_error else ""
        raise RuntimeError(f"{error} (the next scan retries it){also}")
