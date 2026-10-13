# SPDX-License-Identifier: Apache-2.0
"""Phase 2 of a `security scan` run: decide new quarantines for the whole
fleet at once, through the blast-radius circuit breaker, then act.

Phase 1 (security_scan_core, with ``defer_new=True``) scans, persists and
re-asserts existing quarantines per project but takes no NEW quarantine.
Here the run's new quarantines are weighed together (cve/breaker.py); the
ones the breaker lets through are applied under each project's lock,
re-checking state that may have changed since phase 1.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from boxmunge.commands.security_enforce import announce_quarantine, enforce, headline_of
from boxmunge.commands.security_scan_core import ProjectScan
from boxmunge.commands.security_scan_inputs import load_project_meta
from boxmunge.cve.alerting import format_breaker_held_alert, send_alerts
from boxmunge.cve.breaker import (
    Candidate,
    alert_pending,
    decide,
    read_held,
    trip_threshold,
    write_held,
)
from boxmunge.cve.policy import Disposition, ProjectDecision
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scan_state import decisions_from_scan_state, read_scan_state
from boxmunge.fileutil import LockError, project_lock
from boxmunge.log import log_operation, log_warning
from boxmunge.manifest import ManifestError
from boxmunge.paths import BoxPaths


@dataclass
class PhaseTwo:
    applied: list[str] = field(default_factory=list)
    held: dict[str, frozenset[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def _candidate(decisions: tuple[ProjectDecision, ...]) -> Candidate:
    quarantining = [f for d in decisions for f in d.findings
                    if f.disposition == Disposition.QUARANTINE]
    return Candidate(
        cves=frozenset(f.finding.cve_id for f in quarantining),
        kev=any(f.kev_listed for f in quarantining),
    )


def _apply(paths: BoxPaths, project: str, decisions: tuple[ProjectDecision, ...]) -> str | None:
    """Quarantine ``project`` under its lock. Returns an error or None."""
    headline = headline_of(decisions)
    if headline is None:
        return None
    try:
        with project_lock(project, paths):
            if is_quarantined(project, paths):
                return None  # another run got there first
            meta = load_project_meta(paths, project)
            outcome = enforce(
                paths, project, hosts=meta.hosts, compose_files=meta.compose_files,
                headline=headline, in_grace=False,
            )
    except LockError:
        return "held by another operation; the next scan quarantines it"
    except (RuntimeError, ManifestError, OSError) as e:
        return str(e)
    if outcome.landed:
        announce_quarantine(paths, project, decisions)
    return outcome.error


def apply_new_quarantines(
    paths: BoxPaths, scans: Mapping[str, ProjectScan], *, in_grace: bool,
) -> PhaseTwo:
    """Weigh this run's new quarantines together and act on the verdict.

    Raises BreakerError when the held-state file is unreadable: nothing new
    is applied, and the caller reports it loudly.
    """
    result = PhaseTwo()
    already = read_held(paths)
    pending = alert_pending(paths)
    if in_grace:
        result.held = already
        return result
    candidates = {
        name: _candidate(scan.decisions) for name, scan in scans.items()
        if scan.headline is not None and not is_quarantined(name, paths)
    }
    verdict = decide(candidates, projects_scanned=len(scans), already_held=already)
    for name in sorted(verdict.apply):
        error = _apply(paths, name, scans[name].decisions)
        if error:
            result.errors[name] = error
        else:
            result.applied.append(name)

    # Projects not re-evaluated this run keep their held entries.
    result.held = {**{p: c for p, c in already.items() if p not in scans}, **verdict.held}
    if verdict.newly_held:
        _log_hold(paths, result.held, verdict.newly_held, len(scans))
    # The hold is recorded as alerted only once the alert was delivered;
    # until then every scan retries it.
    if result.held and (verdict.newly_held or pending):
        pending = not _send_hold_alert(paths, result.held, len(scans))
    write_held(paths, result.held, alert_pending=pending and bool(result.held))
    return result


def _log_hold(
    paths: BoxPaths, held: Mapping[str, frozenset[str]],
    newly: frozenset[str], scanned: int,
) -> None:
    log_operation(
        "cve-scan",
        f"circuit breaker held {len(newly)} new quarantine(s): {', '.join(sorted(newly))}",
        paths, project=None,
        detail={"held": {p: sorted(c) for p, c in held.items()},
                "threshold": trip_threshold(scanned), "projects_scanned": scanned},
    )


def _send_hold_alert(paths: BoxPaths, held: Mapping[str, frozenset[str]], scanned: int) -> bool:
    """One priority-1 alert for the whole hold. True if delivered."""
    alert = format_breaker_held_alert(held, threshold=trip_threshold(scanned), scanned=scanned)
    try:
        return send_alerts((alert,), paths) == 1
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning("cve-scan", f"breaker alert emission failed: {e}", paths)
        return False


def apply_held(paths: BoxPaths) -> PhaseTwo:
    """Operator override: apply every held quarantine now.

    Uses each project's persisted scan state (no re-scan), so what is
    applied is exactly what was held. A project whose findings no longer
    quarantine is dropped from the held set without action.
    """
    result = PhaseTwo()
    still_held: dict[str, frozenset[str]] = {}
    for project, cves in sorted(read_held(paths).items()):
        try:
            state = read_scan_state(paths.project_scan_state(project))
            decisions = decisions_from_scan_state(state, project_name=project) if state else ()
        except (ValueError, KeyError, TypeError, OSError) as e:
            result.errors[project] = f"scan state unreadable: {e}"
            still_held[project] = cves
            continue
        error = _apply(paths, project, decisions)
        if error:
            result.errors[project] = error
            still_held[project] = cves
        elif headline_of(decisions) is not None:
            result.applied.append(project)
    write_held(paths, still_held)
    result.held = still_held
    return result
