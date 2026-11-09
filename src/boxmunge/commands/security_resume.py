# SPDX-License-Identifier: Apache-2.0
"""boxmunge security resume <project> — lift a CVE quarantine.

Resume fails closed (audit B-02): the quarantine is lifted only after an
audit-only re-scan of every one of the project's current images succeeds
and shows no quarantine-level finding. A failed image scan, an image the
per-project budget skipped, or a service whose image cannot be identified
keeps the quarantine, because boxmunge cannot show the finding is resolved.
So does a CISA KEV catalog that cannot back the lift (cve.lift_rule, the
rule the deploy gate shares): a stale one that lists the quarantine's CVE
or a CVE in the images, or none at all. `--accept-stale-kev` lifts anyway,
for an operator who has judged that risk: it is logged before the lift and
alerted after it, and says what it gives up. A lift on a stale catalog the
rule allows is alerted the same way, naming what could not be checked.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

from boxmunge.commands.quarantine_lift import restore_from_quarantine
from boxmunge.commands.security_scan_core import ProjectScan, scan_one_project_locked
from boxmunge.cve.lift_rule import (
    ACCEPT_FLAG, KevLiftCheck, accept_advice, check_kev_for_lift, fresh_data_advice,
)
from boxmunge.cve.policy import Disposition, FindingDisposition
from boxmunge.cve.quarantine import (
    QuarantineError, checked_quarantine_record, is_quarantined, read_quarantine_state,
)
from boxmunge.cve.scan_state import BASIS_STARTUP_IMAGES
from boxmunge.cve.kev import load_kev
from boxmunge.cve.kev_withdrawals import KevWithdrawalsError, accept_withdrawals
from boxmunge.cve.scanner import TrivyNotInstalledError, refresh_db
from boxmunge.fileutil import LockError, project_lock
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_warning
from boxmunge.manifest import ManifestError
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _report_incomplete(project: str, scan: ProjectScan) -> None:
    _err(
        f"ERROR: Cannot resume — the re-scan of '{project}' did not cover "
        f"every image, so boxmunge cannot show the quarantine-level findings "
        f"are resolved. The quarantine stays in place."
    )
    for reason in scan.incomplete_reasons():
        _err(f"  - {reason}")
    _err(
        "  Fix the cause (Trivy DB or registry reachability, or a service "
        "image that is not in the local image store), then retry `boxmunge security resume "
        f"{project}`."
    )


def _report_blocking(project: str, blocking: list[FindingDisposition]) -> None:
    # Dedupe by CVE id: one CVE can appear in several packages.
    cve_seen: dict[str, str] = {}
    for f in blocking:
        cve_seen.setdefault(f.finding.cve_id, f.effective_severity.value)
    h = blocking[0]
    _err(
        f"ERROR: Cannot resume — {h.finding.cve_id} "
        f"({h.effective_severity.value}) would still quarantine."
    )
    others = [f"{cve} ({sev})" for cve, sev in cve_seen.items() if cve != h.finding.cve_id]
    if others:
        _err(
            f"  Plus {len(others)} more quarantine-level "
            f"finding{'s' if len(others) != 1 else ''}: {', '.join(others)}"
        )
    _err("  Options:")
    _err(
        f"    - Suppress all current blockers: boxmunge security suppress "
        f"--current --project {project} --until <YYYY-MM-DD> --reason <text>"
    )
    _err(
        f"    - Suppress one: boxmunge security suppress {h.finding.cve_id} "
        f"--project {project} --until <YYYY-MM-DD> --reason <text>"
    )
    _err(f"    - Deploy a release that fixes it: prod-deploy {project} (its images are "
         f"scanned first; the quarantine lifts once it is live).")
    _err("    - Wait for upstream fix and rescan.")


def cmd_security_resume(args: list[str], paths: BoxPaths) -> int:
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args("security", args, flags={ACCEPT_FLAG},
                        min_positional=1, max_positional=1)
    project = require_project_name("security", parsed.positional[0])

    if not is_quarantined(project, paths):
        _err(f"ERROR: project '{project}' is not quarantined.")
        return 1

    # Announce re-scan, not lift: "Resuming" is printed only once it clears.
    print(f"Re-scanning {project} before lift...")
    try:
        refresh_db()
    except TrivyNotInstalledError as e:
        _err(f"ERROR: {e}")
        return 1

    # One lock for the re-scan and the lift: no deploy or container update
    # can change the images between the scan that clears them and the lift
    # that starts them.
    try:
        with project_lock(project, paths):
            return security_resume_locked(paths, project,
                                          accept_stale_kev=parsed.has(ACCEPT_FLAG))
    except LockError:
        _err(f"ERROR: Another operation is in progress for '{project}'. Try again shortly.")
        return 1


def security_resume_locked(paths: BoxPaths, project: str, *,
                           accept_stale_kev: bool = False) -> int:
    """The security-resume core: re-scan, then lift. Caller holds the
    project lock; never takes it."""
    block = is_blocked(project, paths)
    if block is not None and block.reason is BlockReason.MIGRATING:
        _err(f"ERROR: {block.refuse_message}")
        return 1
    if not is_quarantined(project, paths):
        _err(f"ERROR: project '{project}' is not quarantined.")
        return 1
    # audit_only=True (audit A-3): the pre-lift scan must not mutate
    # scan_state.json or emit transition alerts.
    kev = load_kev(paths)
    try:
        scan = scan_one_project_locked(
            paths, project, in_grace=False, kev=kev, audit_only=True,
        )
    except (TrivyNotInstalledError, RuntimeError, ManifestError) as e:
        _err(f"ERROR: {e}")
        _err("  The quarantine stays in place until a re-scan succeeds.")
        return 1

    if not scan.complete:
        _report_incomplete(project, scan)
        return 1

    blocking = [
        f for d in scan.decisions for f in d.findings
        if f.disposition == Disposition.QUARANTINE
    ]
    if blocking:
        _report_blocking(project, blocking)
        return 1
    try:
        record = checked_quarantine_record(read_quarantine_state(project, paths),
                                           paths.project_quarantine_state(project))
    except QuarantineError as e:
        _err(f"ERROR: {e}")
        return 1
    check = check_kev_for_lift(record["cve_id"], scan.decisions, kev,
                               datetime.now(timezone.utc).date())
    if check.refusal is not None and not accept_stale_kev:
        _err(f"ERROR: Cannot resume '{project}' — the re-scan is clear, but "
             f"{check.refusal}. The quarantine stays in place.")
        _err(f"  {fresh_data_advice()}, then retry.")
        _err(f"  {accept_advice(project)}.")
        return 1
    if accept_stale_kev and check.refusal is None:
        print(f"  {ACCEPT_FLAG}: nothing to accept, the KEV catalog backs this lift.")
    elif accept_stale_kev:
        print(f"  {ACCEPT_FLAG}: lifting although {check.refusal}. A CVE that is actively "
              f"exploited may come back online.")
        log_warning("security-resume", f"{ACCEPT_FLAG}: lift accepted on an unusable KEV "
                    f"catalog", paths, project=project,
                    detail={"reason": check.refusal, "kev_stale": check.stale})

    what = ("every image the lift will start" if scan.basis == BASIS_STARTUP_IMAGES
            else "every container's image")
    print(f"  Re-scan: clear ({what} scanned, no quarantine-level findings)")
    print(f"Resuming {project}...")
    rc = _resume_lift(paths, project)
    if rc == 0:
        _accept_withdrawals(paths, project, scan)
        _alert_kev_risk(paths, project, check, accepted=accept_stale_kev)
    return rc


def _accept_withdrawals(paths: BoxPaths, project: str, scan: ProjectScan) -> None:
    """The lift accepts every KEV withdrawal the images still contain, so a
    later quarantine of this project is not held for it again."""
    found = {f.finding.cve_id for d in scan.decisions for f in d.findings}
    try:
        accepted = accept_withdrawals(paths, project, found)
    except KevWithdrawalsError as e:
        _err(f"WARNING: {e}. The quarantine is lifted, but a later quarantine of "
             f"{project} may be held for these withdrawals again.")
        return
    if accepted:
        print(f"  Accepted the CISA KEV withdrawal of {', '.join(accepted)} for {project}.")


def _alert_kev_risk(paths: BoxPaths, project: str, check: KevLiftCheck, *,
                    accepted: bool) -> None:
    """A lift the KEV catalog did not fully back is a priority-1 alert."""
    if check.refusal is not None and accepted:
        title = f"{project}: quarantine lifted with {ACCEPT_FLAG}"
        why = (f"the operator accepted lifting it although {check.refusal} "
               f"(`security resume {ACCEPT_FLAG}`)")
    elif check.gap is not None:
        title = f"{project}: quarantine lifted on a stale KEV catalog"
        why = f"it was lifted although {check.gap}"
    else:
        return
    print(f"  WARNING: {why[0].upper()}{why[1:]}.")
    log_warning("security-resume", title, paths, project=project,
                detail={"reason": why, "kev_stale": check.stale})
    notify(paths, title, f"{project}: {why}. {fresh_data_advice()}.",
           component="security-resume", project=project, priority=1)


def _resume_lift(paths: BoxPaths, project: str) -> int:
    """Inner lift section. Caller MUST hold the per-project lock."""
    try:
        restored = restore_from_quarantine(paths, project, component="security-resume")
    except QuarantineError as e:
        _err(f"ERROR: {e}")
        _err("  The quarantine stays in place.")
        return 1
    if restored.held is not None:
        print(f"  Quarantine lifted. '{project}' stays down: {restored.held}. The "
              f"maintenance page stays up and its containers stay stopped.")
        return 0
    print("  Caddy config restored.")
    print("  Containers started (scanned images, no rebuild).")
    smoke_ok, smoke_msg = restored.smoke
    print("  Smoke test: OK" if smoke_ok else f"  Smoke test: FAIL — {smoke_msg}")
    print(f"Project '{project}' resumed.")
    return 0
