# SPDX-License-Identifier: Apache-2.0
"""Action handlers for `boxmunge security` subcommands: scan and resume.

The suppress/unsuppress handlers live in security_suppress.py — they share
no internals beyond the suppressions-path helper. The per-project scan
mechanics live in security_scan_core.py — keep this file focused on
fleet orchestration (grace heads-up, exit codes, lock-skip handling).
"""
from __future__ import annotations

import fcntl
import os
import sys
import time
from datetime import datetime, timezone

from boxmunge.caddy import prepare_caddy_config
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.compose import prepare_compose_override
from boxmunge.cve.alerting import (
    format_grace_heads_up_alert,
    send_alerts,
)
from boxmunge.cve.grace import (
    GraceError,
    init_grace_if_missing,
    mark_heads_up_sent,
    read_grace_state,
)
from boxmunge.cve.policy import Disposition, ProjectDecision
from boxmunge.cve.quarantine import (
    QuarantineError,
    is_quarantined,
    lift_quarantine,
)
from boxmunge.cve.scanner import TrivyNotInstalledError, refresh_db
from boxmunge.fileutil import LockError, open_shared_lockfile, project_lock
from boxmunge.health_checks.smoke import run_smoke
from boxmunge.log import log_warning
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.paths import BoxPaths, validate_project_name
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
    project: str | None = None
    if args:
        if args[0].startswith("--"):
            print(f"ERROR: unknown argument: {args[0]}", file=sys.stderr)
            return 2
        project = args[0]
        try:
            validate_project_name(project)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2

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

    # Migration grace window — bootstrap lazily on first scan after upgrade.
    # If grace state is corrupt we abort the scan rather than silently
    # proceeding with full enforcement: the operator might believe they
    # are in grace when they are not. (Per-project scans use the same
    # bootstrap so the in_grace flag is consistent across entry-points.)
    now = datetime.now(timezone.utc)
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
            headline, decisions, warnings, posture_str, dangerously = (
                scan_one_project(paths, name, in_grace=in_grace)
            )
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
        for w in warnings:
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
            posture_by_project[name] = posture_str
            dangerously_by_project[name] = dangerously

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


# ---------- subcommand: resume ----------


def cmd_security_resume(args: list[str], paths: BoxPaths) -> int:
    if not args:
        print(
            "Usage: boxmunge security resume <project>", file=sys.stderr,
        )
        return 2
    project = args[0]
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if not is_quarantined(project, paths):
        print(
            f"ERROR: project '{project}' is not quarantined.",
            file=sys.stderr,
        )
        return 1

    print(f"Resuming {project}...")
    try:
        refresh_db()
    except TrivyNotInstalledError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # The pre-lift scan acquires its own per-project lock inside
    # scan_one_project (audit A-2). LockError surfaces as a clear "try
    # again" message rather than a hidden race.
    #
    # audit_only=True (audit A-3): resume's re-scan must NOT mutate
    # scan_state.json or emit transition alerts. Operators don't expect
    # `boxmunge security resume X` to push alerts about X, and clobbering
    # scan_state would obscure the prior context the headline CVE was
    # based on.
    try:
        _, decisions, _, _, _ = scan_one_project(
            paths, project, audit_only=True,
        )
    except LockError:
        print(
            f"ERROR: Another operation is in progress for '{project}'. "
            f"Try again shortly.",
            file=sys.stderr,
        )
        return 1
    except TrivyNotInstalledError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except (RuntimeError, ManifestError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    blocking = []
    for d in decisions:
        for f in d.findings:
            if f.disposition == Disposition.QUARANTINE:
                blocking.append(f)

    if blocking:
        h = blocking[0]
        print(
            f"ERROR: Cannot resume — {h.finding.cve_id} "
            f"({h.effective_severity.value}) would still quarantine.",
            file=sys.stderr,
        )
        print(
            "  Either suppress it (boxmunge security suppress) or wait for "
            "upstream fix.",
            file=sys.stderr,
        )
        return 1

    print("  Re-scan: clear (no quarantine-level findings)")

    # Audit A-2: lift section must hold the per-project lock so
    # config-regen + compose_up + state-clear cannot interleave with a
    # concurrent deploy/promote/container-update.
    try:
        with project_lock(project, paths):
            return _resume_lift(paths, project)
    except LockError:
        print(
            f"ERROR: Another operation is in progress for '{project}'. "
            f"Try again shortly.",
            file=sys.stderr,
        )
        return 1


def _resume_lift(paths: BoxPaths, project: str) -> int:
    """Inner lift section. Caller MUST hold the per-project lock."""
    # Render normal Caddy site config + compose override using the
    # caddy/compose primitives (the resume_cmd flow does the same).
    try:
        manifest = load_manifest(paths.project_manifest(project))
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    try:
        prepare_caddy_config(paths, manifest)
        prepare_compose_override(paths, manifest, component="security-resume")
    except (OSError, ValueError) as e:
        print(f"ERROR: Failed to render Caddy/compose: {e}", file=sys.stderr)
        return 1
    print("  Caddy config restored.")

    site_path = paths.project_caddy_site(project)
    site_content = site_path.read_text() if site_path.exists() else ""
    compose_files = ["compose.yml"]
    if paths.project_compose_override(project).exists():
        compose_files.append("compose.boxmunge.yml")
    try:
        lift_quarantine(
            project, paths,
            project_dir=paths.project_dir(project),
            project_caddy_site_content=site_content,
            compose_files=compose_files,
        )
    except QuarantineError as e:
        print(f"ERROR: lift_quarantine failed: {e}", file=sys.stderr)
        return 1
    print("  Containers started.")

    # Smoke test — shared with the pause/resume flow.
    smoke_ok, smoke_msg = run_smoke(project, paths)
    if smoke_ok:
        print("  Smoke test: OK")
    else:
        print(f"  Smoke test: FAIL — {smoke_msg}")

    print(f"Project '{project}' resumed.")
    return 0
