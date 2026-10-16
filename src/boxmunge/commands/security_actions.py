# SPDX-License-Identifier: Apache-2.0
"""Fleet orchestration for `boxmunge security scan`.

Resume lives in security_resume.py and suppress/unsuppress in
security_suppress.py. The per-project scan mechanics live in
security_scan_core.py — keep this file focused on fleet orchestration
(grace heads-up, exit codes, lock-skip handling).
"""
from __future__ import annotations

import fcntl
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from boxmunge.commands.security_fleet_enforce import apply_held, apply_new_quarantines
from boxmunge.commands.security_scan_core import ProjectScan, scan_one_project
from boxmunge.cve.breaker import BreakerError
from boxmunge.cve.alerting import (
    format_grace_heads_up_alert,
    format_host_suppression_expired_alert,
    format_kev_stale_alert,
    format_scan_failure_alert,
    send_alerts,
)
from boxmunge.cve.kev import KevCatalog, load_kev, refresh_kev
from boxmunge.cve.grace import (
    GraceError,
    init_grace_if_missing,
    mark_heads_up_sent,
    read_grace_state,
)
from boxmunge.cve.policy import Disposition, ProjectDecision
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scanner import TrivyNotInstalledError, refresh_db
from boxmunge.fileutil import LockError, open_shared_lockfile
from boxmunge.log import log_warning
from boxmunge.manifest import ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import (
    deployed_among, is_registered, read_registry,
    registry_problem_message,
)


# ---------- helpers ----------


def _maybe_fire_grace_heads_up(
    paths: BoxPaths,
    *,
    decisions_by_project: dict[str, ProjectDecision],
    posture_by_project: dict[str, str],
    dangerously_by_project: dict[str, bool],
) -> None:
    """Fire the one-time grace heads-up alert under a fleet-wide flock.

    Audit E-1: read-decide-write of grace.heads_up_sent must be atomic
    across concurrent fleet scans (cron + manual). Without the lock, two
    scans both pass the ``not heads_up_sent`` check and Pushover is spammed
    twice. The lock file lives at ``state/.cve-grace.lock`` (matches the
    ``.caddy.lock`` / ``.registry.lock`` pattern, shared between root and
    deploy uids).

    Failures of send/persist are logged but never raised — alerting must
    not block the scan.
    """
    lock_path = paths.state / ".cve-grace.lock"
    fd = open_shared_lockfile(lock_path)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        # Re-read inside the lock: another process may have raced us
        # between the outer check and lock acquisition.
        try:
            current = read_grace_state(paths)
        except GraceError as e:
            log_warning(
                "cve-scan",
                f"grace state unreadable while firing heads-up: {e}",
                paths,
            )
            return
        if current is None or current.heads_up_sent:
            return
        alert = format_grace_heads_up_alert(
            expires_at=current.expires_at,
            decisions_by_project=decisions_by_project,
            posture_by_project=posture_by_project,
            dangerously_by_project=dangerously_by_project,
        )
        # Record the heads-up as sent only once it was delivered, so an
        # undelivered one is retried by the next scan in the window.
        if send_alerts((alert,), paths) != 1:
            return
        try:
            mark_heads_up_sent(paths, current)
        except OSError as e:
            log_warning(
                "cve-scan",
                f"failed to persist heads_up_sent flag: {e}",
                paths,
            )
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _refresh_kev_and_alert(paths: BoxPaths, now: datetime) -> KevCatalog:
    """Refresh the CISA KEV catalog once per run and load it.

    The one catalog is threaded into every project scan so the exploitation
    signal is consistent fleet-wide. Fail-safe: a stale catalog never
    quarantines, and a rejected refresh keeps the previous cache (B-06), but
    either fires ONE priority-1 alert per run so the degradation is never
    silent.
    """
    refresh = refresh_kev(paths)
    kev = load_kev(paths)
    stale = kev.is_stale(now.date())
    if not stale and refresh.rejected is None:
        return kev
    log_warning(
        "cve-scan",
        "CISA KEV catalog degraded — exploitation-based quarantine at risk"
        + (f" (refresh rejected: {refresh.rejected})" if refresh.rejected else ""),
        paths, project=None,
        detail={
            "kev_fetched_at": kev.fetched_at.isoformat() if kev.fetched_at else None,
            "stale": stale,
            "rejected": refresh.rejected,
        },
    )
    alert = format_kev_stale_alert(kev.fetched_at, stale=stale, rejected=refresh.rejected)
    try:
        send_alerts((alert,), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning(
            "cve-scan", f"KEV alert emission failed: {e}", paths, project=None,
        )
    return kev


def _summarise_decisions(decisions: list[ProjectDecision]) -> str:
    """One-line counts of dispositions across all decisions."""
    counts: dict[str, int] = {}
    total = 0
    for d in decisions:
        for f in d.findings:
            total += 1
            counts[f.disposition.value] = counts.get(f.disposition.value, 0) + 1
    if total == 0:
        return "0 findings"
    parts = []
    for tag in (
        Disposition.QUARANTINE.value,
        Disposition.SUPPRESSED.value,
        Disposition.STILL_RUNNING_AT_RISK.value,
        Disposition.INFORMATIONAL.value,
        Disposition.IGNORED_FIXED.value,
    ):
        c = counts.get(tag, 0)
        if c:
            parts.append(f"{c} {tag.replace('_', '-')}")
    return f"{total} findings ({', '.join(parts)})"


# ---------- subcommand: scan ----------


@dataclass
class FleetRun:
    """What one `security scan` run learned, project by project."""

    scans: dict[str, ProjectScan] = field(default_factory=dict)
    # project → human lines: a hard error, or each image/service not covered.
    problems: dict[str, list[str]] = field(default_factory=dict)
    skipped_locked: list[str] = field(default_factory=list)
    # Held by the circuit breaker: project → its held CVEs.
    held: dict[str, frozenset[str]] = field(default_factory=dict)


# FleetRun.problems key for a damaged project registry: a fleet-level
# problem, since a bad line names no project that can be scanned.
REGISTRY_PROBLEM = "(project registry)"


def _parse_scan_targets(
    args: list[str], paths: BoxPaths,
) -> tuple[list[str], tuple[str, ...]] | int:
    """Resolve the projects to scan and any registry problems, or return a
    lookup exit code.

    A fleet scan scans every valid registered project and carries each bad
    registry line forward to be reported. Usage errors exit 2 from parse_args.
    """
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args("security", args, max_positional=1)
    if not parsed.positional:
        registry = read_registry(paths)
        return deployed_among(registry.names, paths), registry.problems
    project = require_project_name("security", parsed.positional[0])
    if not is_registered(project, paths):
        print(f"ERROR: project '{project}' is not registered.", file=sys.stderr)
        return 1
    return [project], ()


def _report_registry_problems(
    paths: BoxPaths, run: FleetRun, problems: tuple[str, ...],
) -> None:
    """Carry each bad registry line into the run's problems: printed, logged,
    alerted, and failing the exit code like any project that went unscanned."""
    if not problems:
        return
    message = registry_problem_message(problems)
    print(f"ERROR: {message}", file=sys.stderr)
    log_warning("cve-scan", message, paths, detail={"problems": list(problems)})
    run.problems[REGISTRY_PROBLEM] = list(problems)


def _scan_each(
    paths: BoxPaths, targets: list[str], *, in_grace: bool, kev: KevCatalog,
) -> FleetRun:
    """Scan every target; one project's failure never stops the others.

    Raises TrivyNotInstalledError — no project can be scanned without it.
    """
    run = FleetRun()
    for name in targets:
        try:
            scan = scan_one_project(
                paths, name, in_grace=in_grace, kev=kev, defer_new=True,
            )
        except LockError:
            # Audit A-2: another operation holds the project lock. Skip and
            # warn; the next cron tick will re-attempt.
            run.skipped_locked.append(name)
            log_warning(
                "cve-scan",
                f"scan: skipped project {name} — held by another operation",
                paths, project=name,
            )
            print(f"{name}: SKIPPED — held by another operation; will be "
                  f"picked up on next scan")
            continue
        except (RuntimeError, ManifestError, OSError) as e:
            # Audit B-12: a malformed per-project file is reported for that
            # project and the fleet scan carries on with the rest.
            print(f"{name}: ERROR — {e}")
            log_warning(
                "cve-scan", f"scan failed for {name}: {e}",
                paths, project=name, detail={"error": str(e)},
            )
            run.problems[name] = [str(e)]
            continue
        run.scans[name] = scan
        for w in scan.warnings:
            print(f"{name}: WARN — {w}")
        print(f"{name}: {_summarise_decisions(list(scan.decisions))}")
        if not scan.complete:
            run.problems[name] = scan.incomplete_reasons()
            print(f"{name}: INCOMPLETE — {len(run.problems[name])} image(s) "
                  f"or service(s) not scanned")
    return run


def _enforce_fleet(paths: BoxPaths, run: FleetRun, *, in_grace: bool) -> None:
    """Phase 2: new quarantines for the whole run, via the circuit breaker."""
    try:
        phase2 = apply_new_quarantines(paths, run.scans, in_grace=in_grace)
    except BreakerError as e:
        print(f"ERROR: {e} — no new quarantine was applied this run", file=sys.stderr)
        run.problems["(circuit breaker)"] = [f"{e}; no new quarantine was applied"]
        return
    for name, error in sorted(phase2.errors.items()):
        print(f"{name}: ERROR — {error}")
        run.problems.setdefault(name, []).append(error)
    run.held = phase2.held
    for name in sorted(run.held):
        print(f"{name}: HELD by the circuit breaker "
              f"({', '.join(sorted(run.held[name]))}) — still running")


def _cmd_apply_held(paths: BoxPaths) -> int:
    """`security scan --apply-held`: apply the breaker's held quarantines."""
    try:
        result = apply_held(paths)
    except BreakerError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    for name in result.applied:
        print(f"{name}: quarantined (held by the circuit breaker, now applied)")
    for name, error in sorted(result.errors.items()):
        print(f"{name}: ERROR — {error}", file=sys.stderr)
    if not (result.applied or result.errors):
        print("Nothing held by the circuit breaker.")
    return 1 if result.errors else 0


def _alert_fleet(paths: BoxPaths, run: FleetRun) -> None:
    """Once-per-run alerts: scan failures (audit B-11) and expired
    host-scope suppressions (once, not once per project — B-14)."""
    alerts = []
    if run.problems:
        alerts.append(format_scan_failure_alert(run.problems))
    host_expired = {s.cve_id: s for scan in run.scans.values() for s in scan.host_expired}
    if host_expired:
        alerts.append(format_host_suppression_expired_alert(list(host_expired.values())))
    if not alerts:
        return
    try:
        send_alerts(tuple(alerts), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning("cve-scan", f"fleet alert emission failed: {e}", paths)


def _exit_code(paths: BoxPaths, run: FleetRun) -> int:
    """Audit F-8 / B-11 exit codes.

    1 = a project failed or was only partly scanned (or Trivy is missing);
    2 = scanned, ≥1 project quarantined, at-risk-running or held by the
    circuit breaker; 0 = clean.
    """
    if run.problems:
        print(f"Scan incomplete: {', '.join(sorted(run.problems))}. Exit code 1.")
        return 1
    quarantined = [n for n in run.scans if is_quarantined(n, paths)]
    held = sorted(n for n in run.held if n in run.scans)
    at_risk = [
        n for n, scan in run.scans.items()
        if any(f.disposition == Disposition.STILL_RUNNING_AT_RISK
               for d in scan.decisions for f in d.findings)
    ]
    if not (quarantined or at_risk or held):
        return 0
    bits: list[str] = []
    if held:
        bits.append(f"{len(held)} held by the circuit breaker ({', '.join(held)})")
    if quarantined:
        bits.append(f"{len(quarantined)} quarantined ({', '.join(quarantined)})")
    if at_risk:
        bits.append(f"{len(at_risk)} at-risk-running ({', '.join(at_risk)})")
    print(f"Attention required: {'; '.join(bits)}. Exit code 2.")
    return 2


def cmd_security_scan(args: list[str], paths: BoxPaths) -> int:
    """boxmunge security scan [project] | --apply-held."""
    if args == ["--apply-held"]:
        return _cmd_apply_held(paths)
    parsed = _parse_scan_targets(args, paths)
    if isinstance(parsed, int):
        return parsed
    targets, registry_problems = parsed
    if not targets and not registry_problems:
        print("No projects registered.")
        return 0

    try:
        refresh_db()
    except TrivyNotInstalledError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc)
    kev = _refresh_kev_and_alert(paths, now)

    # Migration grace window — bootstrap lazily on first scan after upgrade.
    # Corrupt grace state aborts the scan rather than silently proceeding
    # with full enforcement: the operator might believe they are in grace.
    try:
        grace = init_grace_if_missing(paths, now=now)
    except GraceError as e:
        print(
            f"ERROR: CVE migration grace state is corrupt: {e}\n"
            f"  Inspect {paths.cve_grace_state} and resolve before scanning.",
            file=sys.stderr,
        )
        return 1
    in_grace = grace.is_active(now=now)

    start = time.monotonic()
    try:
        run = _scan_each(paths, targets, in_grace=in_grace, kev=kev)
    except TrivyNotInstalledError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    _report_registry_problems(paths, run, registry_problems)
    _enforce_fleet(paths, run, in_grace=in_grace)

    # The one-time heads-up needs the whole fleet: fleet scans only.
    if not args and in_grace and not grace.heads_up_sent and run.scans:
        _maybe_fire_grace_heads_up(
            paths,
            decisions_by_project={
                n: s.decisions[0] for n, s in run.scans.items() if s.decisions
            },
            posture_by_project={n: s.posture for n, s in run.scans.items()},
            dangerously_by_project={n: s.dangerously for n, s in run.scans.items()},
        )
    _alert_fleet(paths, run)

    elapsed = time.monotonic() - start
    print(f"Scanned {len(targets)} projects in {elapsed:.1f}s.")
    if run.skipped_locked:
        print(f"Skipped (locked): {', '.join(run.skipped_locked)}")
    if in_grace:
        print(
            f"Migration grace ACTIVE — full enforcement begins "
            f"{grace.expires_at.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC",
        )
    return _exit_code(paths, run)
