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
from datetime import datetime, timezone

from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.cve._alerting_formatters import format_kev_stale_alert
from boxmunge.cve.alerting import (
    format_grace_heads_up_alert,
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
from boxmunge.project_registry import is_registered, load_registered_projects


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
        try:
            send_alerts((alert,), paths)
        except Exception as e:  # noqa: BLE001 — alerting must never block scan
            log_warning(
                "cve-scan", f"heads-up alert send raised: {e}", paths,
            )
        # Persist regardless of delivery success: operator can see grace
        # state in `boxmunge security` and we don't want repeated sends
        # if Pushover is down.
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


def cmd_security_scan(args: list[str], paths: BoxPaths) -> int:
    """boxmunge security scan [project] — scan one or all projects."""
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args("security", args, max_positional=1)
    project: str | None = None
    if parsed.positional:
        project = require_project_name("security", parsed.positional[0])

    if project is not None:
        if not is_registered(project, paths):
            print(
                f"ERROR: project '{project}' is not registered.",
                file=sys.stderr,
            )
            return 1
        targets = [project]
    else:
        targets = sorted(load_registered_projects(paths))

    if not targets:
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
    # If grace state is corrupt we abort the scan rather than silently
    # proceeding with full enforcement: the operator might believe they
    # are in grace when they are not. (Per-project scans use the same
    # bootstrap so the in_grace flag is consistent across entry-points.)
    is_fleet_scan = project is None
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
    failures = 0
    skipped_locked: list[str] = []
    quarantined_projects: list[str] = []
    at_risk_running_projects: list[str] = []
    decisions_by_project: dict[str, ProjectDecision] = {}
    posture_by_project: dict[str, str] = {}
    dangerously_by_project: dict[str, bool] = {}

    for name in targets:
        try:
            scan = scan_one_project(paths, name, in_grace=in_grace, kev=kev)
        except LockError:
            # Audit A-2: another operation holds the project lock. Skip and
            # warn — consistent with upgrade_cmd._restart_projects. The next
            # cron tick will re-attempt.
            skipped_locked.append(name)
            log_warning(
                "cve-scan",
                f"scan: skipped project {name} — held by another operation",
                paths, project=name,
            )
            print(
                f"{name}: SKIPPED — held by another operation; will be "
                f"picked up on next scan",
            )
            continue
        except TrivyNotInstalledError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        except (RuntimeError, ManifestError) as e:
            print(f"{name}: ERROR — {e}")
            failures += 1
            continue
        decisions = list(scan.decisions)
        for w in scan.warnings:
            print(f"{name}: WARN — {w}")
        print(f"{name}: {_summarise_decisions(decisions)}")

        # Track per-project disposition outcomes for the F-8 exit code.
        # is_quarantined() reads the live state file (just written above on
        # the quarantine path); STILL_RUNNING_AT_RISK is observable from
        # the decisions list directly.
        if is_quarantined(name, paths):
            quarantined_projects.append(name)
        for d in decisions:
            for f in d.findings:
                if f.disposition == Disposition.STILL_RUNNING_AT_RISK:
                    if name not in at_risk_running_projects:
                        at_risk_running_projects.append(name)
                    break

        # Capture per-project state for the heads-up summary. We pick the
        # first decision (one image per project for typical deployments;
        # multi-image projects surface the most-severe via findings sort).
        if decisions:
            decisions_by_project[name] = decisions[0]
            posture_by_project[name] = scan.posture
            dangerously_by_project[name] = scan.dangerously

    # Fire the one-time heads-up alert if we're still in grace AND it
    # hasn't already gone out. Fleet scans only — per-project scans never
    # have the full fleet state needed to populate the alert lists.
    if (
        is_fleet_scan
        and in_grace
        and not grace.heads_up_sent
        and decisions_by_project
    ):
        _maybe_fire_grace_heads_up(
            paths,
            decisions_by_project=decisions_by_project,
            posture_by_project=posture_by_project,
            dangerously_by_project=dangerously_by_project,
        )

    elapsed = time.monotonic() - start
    print(f"Scanned {len(targets)} projects in {elapsed:.1f}s.")
    if skipped_locked:
        print(f"Skipped (locked): {', '.join(skipped_locked)}")
    if in_grace:
        print(
            f"Migration grace ACTIVE — full enforcement begins "
            f"{grace.expires_at.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC",
        )

    # Audit F-8: distinguish exit codes so operator scripts can react.
    # 1 = scan failed (Trivy missing handled above; runtime/manifest fails)
    # 2 = scan completed, ≥1 project quarantined or at-risk-running
    # 0 = clean
    if failures > 0:
        return 1
    if quarantined_projects or at_risk_running_projects:
        bits: list[str] = []
        if quarantined_projects:
            bits.append(
                f"{len(quarantined_projects)} quarantined "
                f"({', '.join(quarantined_projects)})",
            )
        if at_risk_running_projects:
            bits.append(
                f"{len(at_risk_running_projects)} at-risk-running "
                f"({', '.join(at_risk_running_projects)})",
            )
        print(f"Attention required: {'; '.join(bits)}. Exit code 2.")
        return 2
    return 0
