# SPDX-License-Identifier: Apache-2.0
"""Fleet orchestration for `boxmunge security scan`.

Resume lives in security_resume.py and suppress/unsuppress in
security_suppress.py. The per-project scan mechanics live in
security_scan_core.py — keep this file focused on fleet orchestration
(exit codes, lock-skip handling).
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from boxmunge.commands.autofix_queue_cmd import after_scan
from boxmunge.commands.autofix_urgent_scan import held_for_patch
from boxmunge.commands.security_fleet_enforce import apply_held, apply_new_quarantines
from boxmunge.commands.security_scan_core import (
    ProjectScan, ScanClock, ScanRecordedError, scan_clock, scan_one_project,
)
from boxmunge.commands.security_scan_targets import (
    orphaned, parse_scan_targets, report_unfinished, retire_grace_marker,
    summarise_decisions,
)
from boxmunge.commands.security_suppression_alerts import (
    SuppressionRun, send_suppression_alerts,
)
from boxmunge.cve.breaker import BreakerError
from boxmunge.cve.alerting import (
    Alert,
    format_scan_digest,
    is_low_urgency,
    format_scan_failure_alert,
    format_scan_unrecorded_alert,
    format_suppression_record_alert,
    send_alerts,
)
from boxmunge.commands.security_kev import refresh_kev_and_alert
from boxmunge.cve.fleet_lock import fleet_lock
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.scan_state import last_scanned_at
from boxmunge.cve.policy import Disposition
from boxmunge.cve.quarantine import QuarantineError, is_quarantined
from boxmunge.cve.scanner import ScanResult, TrivyNotInstalledError, refresh_db
from boxmunge.fileutil import LockError
from boxmunge.log import log_warning
from boxmunge.manifest import ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError
from boxmunge.cve.suppression_impact import Expiry
from boxmunge.cve.suppression_record import repair_hint
from boxmunge.project_registry import registry_problem_message

_parse_scan_targets = parse_scan_targets  # tests resolve it here


# ---------- subcommand: scan ----------


@dataclass
class FleetRun:
    """What one `security scan` run learned, project by project."""

    scans: dict[str, ProjectScan] = field(default_factory=dict)
    # project → human lines: a hard error, or each image/service not covered.
    problems: dict[str, list[str]] = field(default_factory=dict)
    skipped_locked: list[str] = field(default_factory=list)
    # Scanned, but the result could not be written: project → the error.
    unrecorded: dict[str, str] = field(default_factory=dict)
    # Held by the circuit breaker: project → its held CVEs.
    held: dict[str, frozenset[str]] = field(default_factory=dict)
    # Low-urgency alerts held back for the one digest sent at the end.
    digest: list[Alert] = field(default_factory=list)
    # One clock for every project of the run (security_scan_core.ScanClock).
    clock: ScanClock = field(default_factory=scan_clock)
    # Suppressions each scan found expired, failed scans' too (they are
    # recorded, so no later scan finds them again).
    expiries: list[Expiry] = field(default_factory=list)
    # Why the suppression notice record could not be used (fails the run).
    record_problem: str | None = None


# FleetRun.problems key for a circuit breaker that failed: no new quarantine
# of the run was applied.
BREAKER_PROBLEM = "(circuit breaker)"

# FleetRun.problems key for a damaged project registry: a fleet-level
# problem, since a bad line names no project that can be scanned.
REGISTRY_PROBLEM = "(project registry)"


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
    paths: BoxPaths, targets: list[str], *, kev: KevCatalog, run: FleetRun,
) -> None:
    """Scan every target; one project's failure never stops the others.

    Raises TrivyNotInstalledError — no project can be scanned without it.
    """
    scanned: dict[str, ScanResult] = {}  # Trivy results by exact image ref
    batch = len(targets) > 1  # a lone project has no fleet to batch with
    for name in targets:
        collected: list[Alert] = []
        try:
            scan = scan_one_project(paths, name, kev=kev, defer_new=True,
                                    scanned=scanned, alerts=collected, clock=run.clock)
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
        except (RuntimeError, ManifestError, OSError, StateError, QuarantineError) as e:
            # Audit B-12: a malformed per-project file (a manifest, a corrupt
            # health, deploy, pause or quarantine record) is reported for
            # that project and the fleet scan carries on with the rest.
            if isinstance(e, ScanRecordedError) and e.expiry:
                run.expiries.append(e.expiry)  # recorded: no later scan finds it
            print(f"{name}: ERROR — {e}")
            log_warning(
                "cve-scan", f"scan failed for {name}: {e}",
                paths, project=name, detail={"error": str(e)},
            )
            run.problems[name] = [str(e)]
            continue
        finally:
            _deliver(paths, run, collected, batch=batch)
        run.scans[name] = scan  # enforced and alerted even if unrecorded
        if scan.expired:
            run.expiries.append(Expiry(name, scan.posture, scan.expired, scan.decisions))
        if scan.record_error:
            print(f"{name}: ERROR — {scan.record_error}")
            log_warning(
                "cve-scan", f"scan of {name} could not be recorded: {scan.record_error}",
                paths, project=name, detail={"error": scan.record_error},
            )
            run.unrecorded[name] = scan.record_error
        for w in scan.warnings:
            print(f"{name}: WARN — {w}")
        print(f"{name}: {summarise_decisions(list(scan.decisions))}")
        if scan.lifted:
            print(f"{name}: quarantine lifted ({scan.lifted})")
        if scan.kept:
            print(f"{name}: {scan.kept}")
        if not scan.complete:
            run.problems[name] = scan.incomplete_reasons()
            print(f"{name}: INCOMPLETE — {len(run.problems[name])} image(s) "
                  f"or service(s) not scanned")


def _deliver(paths: BoxPaths, run: FleetRun, collected: list[Alert], *,
             batch: bool) -> None:
    """Urgent alerts go out now; low-urgency ones wait for the digest when
    the run covers several projects. Delivery is best-effort."""
    now = [a for a in collected if not (batch and is_low_urgency(a))]
    run.digest.extend(a for a in collected if batch and is_low_urgency(a))
    if not now:
        return
    try:
        send_alerts(tuple(now), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning("cve-scan", f"alert delivery failed: {e}", paths)


def _send_digest(paths: BoxPaths, run: FleetRun) -> None:
    """Send the collected low-urgency alerts as one digest. Runs even when
    the scan loop dies midway: those projects' state is already recorded, so
    their findings would never be alerted again."""
    if not run.digest:
        return
    digest = format_scan_digest(run.digest)
    run.digest.clear()
    try:
        send_alerts((digest,), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning("cve-scan", f"scan digest delivery failed: {e}", paths)


def _enforce_fleet(paths: BoxPaths, run: FleetRun) -> None:
    """Phase 2: new quarantines for the whole run, via the circuit breaker."""
    try:
        phase2 = apply_new_quarantines(paths, run.scans)
    except BreakerError as e:
        print(f"ERROR: {e} — no new quarantine was applied this run", file=sys.stderr)
        run.problems[BREAKER_PROBLEM] = [f"{e}; no new quarantine was applied"]
        return
    for name, error in sorted(phase2.errors.items()):
        print(f"{name}: ERROR — {error}")
        run.problems.setdefault(name, []).append(error)
    run.held = phase2.held
    for name in sorted(run.held):
        print(f"{name}: HELD by the circuit breaker "
              f"({', '.join(sorted(run.held[name]))}) — still running")
    notices = held_for_patch(paths, run.held)   # held: patched with the site up
    if notices:
        _deliver(paths, run, notices, batch=False)


def scan_projects(paths: BoxPaths, targets: list[str], *, kev: KevCatalog,
                  quiet: frozenset[str] = frozenset()) -> FleetRun:
    """The scan loop of a fleet run over exactly ``targets``: scan each,
    send the digest, apply the new quarantines through the circuit breaker
    and send the run's alerts (but not the failure of a ``quiet`` project).
    Raises TrivyNotInstalledError.

    The circuit breaker sees only ``targets`` here, so its trip threshold
    (a share of the projects scanned, here only the affected ones) is
    smaller than in the nightly run: for non-KEV candidates a few projects
    hit by one listing can trip it. Deliberate (one CVE hitting many
    projects is what it guards against); KEV candidates are never held, and
    a held quarantine is the operator's to apply (`scan --apply-held`)."""
    run = FleetRun()
    try:
        try:
            _scan_each(paths, targets, kev=kev, run=run)
        finally:
            _send_digest(paths, run)
        _enforce_fleet(paths, run)
    finally:
        _alert_suppressions(paths, run, full=False)
    _alert_fleet(paths, run, quiet=quiet)
    return run


def _alert_suppressions(paths: BoxPaths, run: FleetRun, *, full: bool) -> None:
    """Suppression expiries and warnings, after the run's enforcement or from
    a ``finally`` when the run died (what its scans recorded must still be
    alerted). ``full``: the run judged the whole fleet, so host scope is
    alerted (security_suppression_alerts)."""
    unjudged = [n for n in (*run.problems, *run.skipped_locked)
                if n not in run.scans and not n.startswith("(")]
    problem = send_suppression_alerts(paths, SuppressionRun(
        scans=run.scans, expiries=run.expiries, held=run.held, unjudged=unjudged,
        full=full, today=run.clock.today, now=run.clock.now))
    if problem:
        print(f"ERROR: {problem}", file=sys.stderr)
        log_warning("cve-scan", problem, paths)
        run.record_problem = problem


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


def _alert_fleet(paths: BoxPaths, run: FleetRun, *, quiet: frozenset[str] = frozenset(),
                 full: bool = False) -> None:
    """Once-per-run alerts: scan failures (audit B-11) and, from a ``full``
    run only (so once a night), an unusable suppression notice record.
    ``quiet`` names projects whose scan failure is not alerted again (the
    KEV watch, once a day)."""
    alerts = []
    if full and run.record_problem:
        alerts.append(format_suppression_record_alert(
            str(paths.suppression_notices), run.record_problem, repair_hint(paths)))
    problems = {p: r for p, r in run.problems.items() if p not in quiet}
    if problems:
        alerts.append(format_scan_failure_alert(problems))
    if run.unrecorded:
        last: dict[str, str | None] = {}
        unreadable: dict[str, str] = {}
        for p in run.unrecorded:
            try:
                last[p] = last_scanned_at(paths.project_scan_state(p))
            except StateError as e:
                unreadable[p] = str(e)
        alerts.append(format_scan_unrecorded_alert(run.unrecorded, last, unreadable))
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
    if run.problems or run.unrecorded or run.record_problem:
        record = {"(suppression notice record)"} if run.record_problem else set()
        failed = sorted({*run.problems, *run.unrecorded} | record)
        print(f"Scan incomplete: {', '.join(failed)}. Exit code 1.")
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
    from boxmunge.lifecycle import migration_refusal
    refusal = migration_refusal("security scan", paths)
    if refusal:  # a quarantine would stop a project mid-migration
        print(f"ERROR: {refusal}", file=sys.stderr)
        return 1
    if args == ["--apply-held"]:
        return _cmd_apply_held(paths)
    if args:  # one project: its own lock is the whole guard, for its patch too
        return _with_urgent(paths, _scan_targets_cmd(args, paths), only=args[:1])

    def waiting() -> None:
        print("waiting for the KEV watch to finish")
        log_warning("cve-scan", "fleet scan: waiting for the KEV watch to finish", paths)

    with fleet_lock(paths, wait=True, on_wait=waiting):
        return _with_urgent(paths, _scan_targets_cmd(args, paths))


def _with_urgent(paths: BoxPaths, rc: int, *, only: list[str] | None = None) -> int:
    """Hand the run's urgent patches on (autofix_queue_cmd.after_scan: the
    autofix unit as root, else run here); one run here that failed has
    applied its fallback and needs attention (exit 2)."""
    outcomes = after_scan(paths, only=only)
    return 2 if rc == 0 and any(not o.ok for o in outcomes) else rc


def _scan_targets_cmd(args: list[str], paths: BoxPaths) -> int:
    parsed = parse_scan_targets(args, paths)
    if isinstance(parsed, int):
        return parsed
    targets, registry_problems, missing = parsed
    report_unfinished(paths, missing)
    orphans = orphaned(missing)
    if not targets and not registry_problems and not orphans:
        print("No deployed projects to scan." if missing else "No projects registered.")
        if not args:  # the fleet run: the deploy guard needs the lists before a first deploy
            refresh_kev_and_alert(paths, datetime.now(timezone.utc))
            print("Known-exploited lists refreshed.")
        return 0

    try:
        refresh_db()
    except TrivyNotInstalledError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc)
    kev = refresh_kev_and_alert(paths, now)

    retire_grace_marker(paths)

    start = time.monotonic()
    run = FleetRun()
    finished = False
    try:
        try:
            _scan_each(paths, targets, kev=kev, run=run)
        except TrivyNotInstalledError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        finally:
            _send_digest(paths, run)
        _report_registry_problems(paths, run, registry_problems)
        for name, reasons in orphans.items():
            print(f"{name}: ERROR — {reasons[0]}")
            log_warning("cve-scan", f"{name}: {reasons[0]}", paths, project=name)
            run.problems[name] = reasons
        _enforce_fleet(paths, run)
        finished = True
    finally:
        # Even a run that died sends what its scans recorded; only a whole
        # fleet run that finished judges host scope.
        _alert_suppressions(paths, run, full=finished and not args)
    _alert_fleet(paths, run, full=not args)

    elapsed = time.monotonic() - start
    print(f"Scanned {len(targets)} projects in {elapsed:.1f}s.")
    if run.skipped_locked:
        print(f"Skipped (locked): {', '.join(run.skipped_locked)}")
    return _exit_code(paths, run)
