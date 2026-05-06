# SPDX-License-Identifier: Apache-2.0
"""boxmunge security — fleet-wide and per-project security view + CVE actions.

Dispatches:
    boxmunge security                                  # fleet summary
    boxmunge security --json                           # fleet summary, JSON
    boxmunge security <project>                        # per-project view
    boxmunge security <project> --json                 # per-project, JSON
    boxmunge security scan [project]                   # scan
    boxmunge security suppress <CVE> --project ...     # suppress
    boxmunge security unsuppress <CVE> --project ...   # unsuppress
    boxmunge security resume <project>                 # lift quarantine
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

from boxmunge.commands.security_actions import (
    cmd_security_resume,
    cmd_security_scan,
)
from boxmunge.commands.security_suppress import (
    cmd_security_suppress,
    cmd_security_unsuppress,
)
from boxmunge.commands.security_views import (
    format_fleet_json,
    format_fleet_text,
    format_project_json,
    format_project_text,
)
from boxmunge.cve.grace import GraceError, read_grace_state
from boxmunge.cve.scan_state import read_scan_state
from boxmunge.cve.quarantine import is_quarantined, read_quarantine_state
from boxmunge.cve.suppressions import (
    SuppressionsError,
    active_suppressions,
    load_suppressions,
)
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import load_registered_projects


USAGE = """\
Usage:
  boxmunge security                                    Fleet-wide summary
  boxmunge security --json                             Fleet-wide JSON
  boxmunge security <project> [--json]                 Per-project view
  boxmunge security scan [project]                     Scan all/one project(s)
  boxmunge security suppress <CVE> --project <name> --until <YYYY-MM-DD> --reason <text>
  boxmunge security unsuppress <CVE> --project <name>
  boxmunge security resume <project>                   Lift CVE quarantine
"""

_SUBCOMMANDS = {"scan", "suppress", "unsuppress", "resume"}


def _paths() -> BoxPaths:
    return BoxPaths()


# ---------- per-project view ----------


def _suppressions_path(paths: BoxPaths, project: str):
    return paths.project_dir(project) / "security" / "suppressions.yml"


def _per_project_view(project: str, as_json: bool, paths: BoxPaths) -> int:
    manifest_path = paths.project_manifest(project)
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if "schema_version" not in manifest:
        print(
            f"ERROR: manifest for project '{project}' is missing schema_version",
            file=sys.stderr,
        )
        return 1

    sec_block = manifest.get("security") or {}
    posture = sec_block.get("posture") or "balanced"
    dangerously = bool(sec_block.get("dangerously_disable_quarantine", False))

    quarantined = is_quarantined(project, paths)
    qstate = read_quarantine_state(project, paths) if quarantined else None
    scan_state = read_scan_state(paths.project_scan_state(project))

    try:
        supps = load_suppressions(_suppressions_path(paths, project))
    except SuppressionsError as e:
        print(f"ERROR: failed to load suppressions: {e}", file=sys.stderr)
        return 1
    today = datetime.now(timezone.utc).date()
    active = active_suppressions(supps, today=today)

    if as_json:
        print(format_project_json(
            manifest,
            posture=posture,
            dangerously_disable_quarantine=dangerously,
            quarantined=quarantined,
            quarantine_state=qstate,
            scan_state=scan_state,
            active_suppressions=active,
        ))
    else:
        print(format_project_text(
            manifest,
            posture=posture,
            dangerously_disable_quarantine=dangerously,
            quarantined=quarantined,
            quarantine_state=qstate,
            scan_state=scan_state,
            active_suppressions=active,
        ))
    return 0


# ---------- fleet summary ----------


def _fleet_summary(paths: BoxPaths) -> dict:
    """Aggregate state across all registered projects."""
    projects = sorted(load_registered_projects(paths))
    posture_dist = {"balanced": 0, "strict": 0, "relaxed": 0}
    quarantined_list: list[dict] = []
    at_risk: list[str] = []
    active_supps_count = 0
    projects_with_supps = 0
    last_scans: list[str] = []

    today = datetime.now(timezone.utc).date()

    for name in projects:
        try:
            manifest = load_manifest(paths.project_manifest(name))
        except ManifestError:
            continue
        sec_block = manifest.get("security") or {}
        posture = (sec_block.get("posture") or "balanced").lower()
        if posture in posture_dist:
            posture_dist[posture] += 1

        if is_quarantined(name, paths):
            qstate = read_quarantine_state(name, paths) or {}
            quarantined_list.append({
                "project": name,
                "cve_id": qstate.get("cve_id", ""),
                "severity": qstate.get("effective_severity") or qstate.get("severity", ""),
                "since": qstate.get("quarantined_at"),
            })

        if bool(sec_block.get("dangerously_disable_quarantine", False)):
            at_risk.append(name)

        scan_state = read_scan_state(paths.project_scan_state(name))
        if scan_state and scan_state.get("scanned_at"):
            last_scans.append(scan_state["scanned_at"])

        try:
            supps = load_suppressions(_suppressions_path(paths, name))
        except SuppressionsError:
            supps = ()
        active = active_suppressions(supps, today=today)
        if active:
            projects_with_supps += 1
            active_supps_count += len(active)

    grace_payload = _grace_payload(paths, now=datetime.now(timezone.utc))

    return {
        "projects_count": len(projects),
        "posture_distribution": posture_dist,
        "quarantined": quarantined_list,
        "at_risk_running": at_risk,
        "active_suppressions_count": active_supps_count,
        "active_suppressions_projects": projects_with_supps,
        "last_fleet_scan": max(last_scans) if last_scans else None,
        "grace": grace_payload,
    }


def _grace_payload(paths: BoxPaths, *, now: datetime) -> dict | None:
    """Build the grace block for the fleet summary, or None if no file.

    Corrupt grace state surfaces as a flag the operator can see in the
    summary; we don't crash the read-side view over a bad file.
    """
    try:
        state = read_grace_state(paths)
    except GraceError as e:
        return {
            "active": False,
            "installed_at": None,
            "expires_at": None,
            "heads_up_sent": False,
            "error": str(e),
        }
    if state is None:
        return None
    return {
        "active": state.is_active(now=now),
        "installed_at": state.installed_at.isoformat(),
        "expires_at": state.expires_at.isoformat(),
        "heads_up_sent": state.heads_up_sent,
    }


# ---------- entry ----------


def cmd_security(args: list[str]) -> None:
    """Top-level dispatcher.

    No args         → fleet summary.
    First is sub    → subcommand handler.
    Else            → per-project view.
    """
    if args and args[0] in ("-h", "--help"):
        print(USAGE)
        sys.exit(0)

    paths = _paths()

    # Subcommand routing.
    if args and args[0] in _SUBCOMMANDS:
        sub = args[0]
        rest = args[1:]
        if sub == "scan":
            sys.exit(cmd_security_scan(rest, paths))
        if sub == "suppress":
            sys.exit(cmd_security_suppress(rest, paths))
        if sub == "unsuppress":
            sys.exit(cmd_security_unsuppress(rest, paths))
        if sub == "resume":
            sys.exit(cmd_security_resume(rest, paths))

    # Flag validation: only --json is accepted on the read paths.
    known_flags = {"--json"}
    unknown = [a for a in args if a.startswith("--") and a not in known_flags]
    if unknown:
        print(
            f"ERROR: unknown argument(s): {' '.join(unknown)}",
            file=sys.stderr,
        )
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    as_json = "--json" in args
    positional = [a for a in args if not a.startswith("--")]

    if not positional:
        # Fleet summary.
        registered = load_registered_projects(paths)
        if not registered:
            if as_json:
                print(format_fleet_json({
                    "projects_count": 0,
                    "posture_distribution": {"balanced": 0, "strict": 0, "relaxed": 0},
                    "quarantined": [],
                    "at_risk_running": [],
                    "active_suppressions_count": 0,
                    "active_suppressions_projects": 0,
                    "last_fleet_scan": None,
                    "grace": _grace_payload(
                        paths, now=datetime.now(timezone.utc),
                    ),
                }))
            else:
                print("No projects registered.")
            return
        summary = _fleet_summary(paths)
        if as_json:
            print(format_fleet_json(summary))
        else:
            print(format_fleet_text(summary))
        return

    if len(positional) > 1:
        print(
            f"ERROR: unknown argument(s): {' '.join(positional[1:])}",
            file=sys.stderr,
        )
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    project = positional[0]
    rc = _per_project_view(project, as_json, paths)
    if rc != 0:
        sys.exit(rc)
