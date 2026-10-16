# SPDX-License-Identifier: Apache-2.0
"""boxmunge security resume <project> — lift a CVE quarantine.

Resume fails closed (audit B-02): the quarantine is lifted only after an
audit-only re-scan of every one of the project's current images succeeds
and shows no quarantine-level finding. A failed image scan, an image the
per-project budget skipped, or a service whose image cannot be identified
keeps the quarantine, because boxmunge cannot show the finding is resolved.
"""
from __future__ import annotations

import sys

from boxmunge.caddy import prepare_caddy_config
from boxmunge.commands.security_scan_core import ProjectScan, scan_one_project
from boxmunge.compose import prepare_compose_override
from boxmunge.cve.policy import Disposition, FindingDisposition
from boxmunge.cve.quarantine import QuarantineError, is_quarantined, lift_quarantine
from boxmunge.cve.scan_state import BASIS_STARTUP_IMAGES
from boxmunge.cve.scanner import TrivyNotInstalledError, refresh_db
from boxmunge.fileutil import LockError, project_lock
from boxmunge.health_checks.smoke import run_smoke
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.pause import is_paused
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
    _err("    - Wait for upstream fix and rescan.")


def cmd_security_resume(args: list[str], paths: BoxPaths) -> int:
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args("security", args, min_positional=1, max_positional=1)
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

    # audit_only=True (audit A-3): the pre-lift scan must not mutate
    # scan_state.json or emit transition alerts.
    try:
        scan = scan_one_project(paths, project, audit_only=True)
    except LockError:
        _err(f"ERROR: Another operation is in progress for '{project}'. Try again shortly.")
        return 1
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

    what = ("every image the lift will start" if scan.basis == BASIS_STARTUP_IMAGES
            else "every container's image")
    print(f"  Re-scan: clear ({what} scanned, no quarantine-level findings)")
    print(f"Resuming {project}...")

    # Audit A-2: the lift holds the per-project lock so config-regen +
    # compose_up + state-clear cannot interleave with a concurrent deploy.
    try:
        with project_lock(project, paths):
            return _resume_lift(paths, project)
    except LockError:
        _err(f"ERROR: Another operation is in progress for '{project}'. Try again shortly.")
        return 1


def _lift_keeping_pause(paths: BoxPaths, project: str) -> int:
    """Lift the quarantine of a project that is also paused (B-20).

    The pause is the operator's own decision, so the project stays down:
    maintenance page kept, containers left stopped. `boxmunge resume`
    brings it back.
    """
    try:
        lift_quarantine(
            project, paths, project_dir=paths.project_dir(project),
            project_caddy_site_content=None, compose_files=[],
        )
    except QuarantineError as e:
        _err(f"ERROR: lift_quarantine failed: {e}")
        return 1
    print(f"  Quarantine lifted. '{project}' is still paused: the maintenance "
          f"page stays up and its containers stay stopped.")
    print(f"  Run `boxmunge resume {project}` to bring it back.")
    return 0


def _resume_lift(paths: BoxPaths, project: str) -> int:
    """Inner lift section. Caller MUST hold the per-project lock."""
    if is_paused(project, paths):
        return _lift_keeping_pause(paths, project)
    try:
        manifest = load_manifest(paths.project_manifest(project))
    except ManifestError as e:
        _err(f"ERROR: {e}")
        return 1
    try:
        prepare_caddy_config(paths, manifest)
        prepare_compose_override(paths, manifest, component="security-resume")
    except (OSError, ValueError) as e:
        _err(f"ERROR: Failed to render Caddy/compose: {e}")
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
        _err(f"ERROR: lift_quarantine failed: {e}")
        return 1
    print("  Containers started (scanned images, no rebuild).")

    smoke_ok, smoke_msg = run_smoke(project, paths)
    if smoke_ok:
        print("  Smoke test: OK")
    else:
        print(f"  Smoke test: FAIL — {smoke_msg}")

    print(f"Project '{project}' resumed.")
    return 0
