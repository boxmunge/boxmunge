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
from dataclasses import dataclass
from datetime import datetime, timezone

from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.commands.security_resume import cmd_security_resume
from boxmunge.commands.security_suppress import cmd_security_suppress
from boxmunge.commands.security_unsuppress import cmd_security_unsuppress
from boxmunge.commands.security_views import (
    format_fleet_json,
    format_fleet_text,
    format_project_json,
    format_project_text,
)
from boxmunge.cve.breaker import BreakerError, read_held
from boxmunge.cve.policy import Disposition
from boxmunge.cve.grace import GraceError, read_grace_state
from boxmunge.cve.scan_state import read_scan_state
from boxmunge.cve.quarantine import (
    QuarantineError, checked_quarantine_record, is_quarantined, read_quarantine_state,
)
from boxmunge.cve.suppressions import (
    SCOPE_HOST,
    SuppressionsError,
    active_suppressions,
    load_suppressions,
)
from boxmunge.fleet import PROJECT_INPUT_ERRORS
from boxmunge.log import log_error
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.run_as import RunAsError, read_users
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import read_registry
from boxmunge.state import StateError


USAGE = """\
Usage:
  boxmunge security                                    Fleet-wide summary
  boxmunge security --json                             Fleet-wide JSON
  boxmunge security <project> [--json]                 Per-project view
  boxmunge security scan [project]                     Scan all/one project(s)
  boxmunge security scan --apply-held                  Apply breaker-held quarantines (operator)
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


class SecurityViewError(Exception):
    """A project's security view cannot be built from its files."""


@dataclass(frozen=True)
class ProjectSecurity:
    """Everything the per-project security views render."""

    manifest: dict
    posture: str
    dangerously_disable_quarantine: bool
    quarantined: bool
    quarantine_state: dict | None
    scan_state: dict | None
    active_suppressions: tuple
    users: dict


def load_project_security(project: str, paths: BoxPaths) -> ProjectSecurity:
    """Read a project's security state. Raises SecurityViewError, with the
    message the CLI prints, when the manifest, quarantine record, scan
    state or suppressions are unusable."""
    try:
        manifest = load_manifest(paths.project_manifest(project))
    except ManifestError as e:
        raise SecurityViewError(str(e)) from e
    if "schema_version" not in manifest:
        raise SecurityViewError(
            f"manifest for project '{project}' is missing schema_version")

    sec_block = manifest.get("security") or {}
    quarantined = is_quarantined(project, paths)
    try:
        qstate = checked_quarantine_record(
            read_quarantine_state(project, paths), paths.project_quarantine_state(project),
        ) if quarantined else None
        scan_state = read_scan_state(paths.project_scan_state(project))
    except (QuarantineError, StateError) as e:
        raise SecurityViewError(str(e)) from e
    try:
        supps = load_suppressions(_suppressions_path(paths, project))
    except SuppressionsError as e:
        raise SecurityViewError(f"failed to load suppressions: {e}") from e
    try:
        users = read_users(paths, project)
    except RunAsError as e:
        raise SecurityViewError(str(e)) from e
    today = datetime.now(timezone.utc).date()
    return ProjectSecurity(
        manifest=manifest,
        posture=sec_block.get("posture") or "balanced",
        dangerously_disable_quarantine=bool(
            sec_block.get("dangerously_disable_quarantine", False)),
        quarantined=quarantined,
        quarantine_state=qstate,
        scan_state=scan_state,
        active_suppressions=active_suppressions(supps, today=today),
        users=users,
    )


def _per_project_view(project: str, as_json: bool, paths: BoxPaths) -> int:
    try:
        view = load_project_security(project, paths)
    except SecurityViewError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    render = format_project_json if as_json else format_project_text
    print(render(
        view.manifest,
        posture=view.posture,
        dangerously_disable_quarantine=view.dangerously_disable_quarantine,
        quarantined=view.quarantined,
        quarantine_state=view.quarantine_state,
        scan_state=view.scan_state,
        active_suppressions=view.active_suppressions,
        users=view.users,
    ))
    return 0


# ---------- fleet summary ----------


@dataclass(frozen=True)
class _FleetFacts:
    """One project's contribution to the fleet summary."""

    posture: str
    quarantine: dict | None
    at_risk: bool
    scanned_at: str | None
    active_suppressions: int


def _fleet_facts(name: str, paths: BoxPaths, today) -> _FleetFacts:
    """Read everything the fleet summary needs from one project. Raises
    PROJECT_INPUT_ERRORS or SuppressionsError when a file is unreadable."""
    manifest = load_manifest(paths.project_manifest(name))
    sec_block = manifest.get("security") or {}
    quarantine = None
    if is_quarantined(name, paths):
        qstate = checked_quarantine_record(
            read_quarantine_state(name, paths), paths.project_quarantine_state(name))
        quarantine = {
            "project": name,
            "cve_id": qstate["cve_id"],
            "severity": qstate["effective_severity"] or qstate["severity"],
            "since": qstate["quarantined_at"],
        }
    scan_state = read_scan_state(paths.project_scan_state(name))
    # At risk = opted out of quarantine AND carrying findings that would
    # otherwise quarantine, not merely opted out.
    at_risk = bool(sec_block.get("dangerously_disable_quarantine", False)) and any(
        f.get("disposition") == Disposition.STILL_RUNNING_AT_RISK.value
        for d in (scan_state or {}).get("decisions", [])
        for f in d.get("findings", [])
    )
    supps = load_suppressions(_suppressions_path(paths, name))
    return _FleetFacts(
        posture=(sec_block.get("posture") or "balanced").lower(),
        quarantine=quarantine,
        at_risk=at_risk,
        scanned_at=(scan_state or {}).get("scanned_at") or None,
        active_suppressions=len(active_suppressions(supps, today=today)),
    )


def fleet_summary(paths: BoxPaths) -> dict:
    """Aggregate state across all registered projects.

    A project whose files cannot be read is listed under "unreadable" (a
    key present only when something is) with the reason, never silently
    left out of the counts; so is each registry line that is not a project
    name, with a null project like the other box-wide files. A registered project with no manifest yet, with
    or without a directory, is not deployed and has no security state.
    """
    registry = read_registry(paths)
    projects = sorted(registry.names)
    posture_dist = {"relaxed": 0, "balanced": 0, "strict": 0, "paranoid": 0}
    quarantined_list: list[dict] = []
    at_risk: list[str] = []
    active_supps_count = 0
    projects_with_supps = 0
    last_scans: list[str] = []
    unreadable: list[dict] = [{"project": None, "error": p} for p in registry.problems]

    today = datetime.now(timezone.utc).date()

    for name in projects:
        try:
            if not paths.project_manifest(name).exists():
                continue
            facts = _fleet_facts(name, paths, today)
        except (*PROJECT_INPUT_ERRORS, SuppressionsError) as e:
            unreadable.append({"project": name, "error": str(e)})
            continue
        if facts.posture in posture_dist:
            posture_dist[facts.posture] += 1
        if facts.quarantine is not None:
            quarantined_list.append(facts.quarantine)
        if facts.at_risk:
            at_risk.append(name)
        if facts.scanned_at:
            last_scans.append(facts.scanned_at)
        if facts.active_suppressions:
            projects_with_supps += 1
            active_supps_count += facts.active_suppressions

    grace_payload = _grace_payload(paths, now=datetime.now(timezone.utc))

    # Host-scope suppressions apply to every project on the box, so they live
    # in one file rather than per-project ones. Counting only the per-project
    # files above would report an active host suppression as 0 — hiding it
    # from the review workflow that is meant to catch it before it lapses.
    try:
        host_supps = load_suppressions(paths.host_suppressions, scope=SCOPE_HOST)
    except SuppressionsError as e:
        host_supps = ()
        unreadable.append({"project": None, "error": str(e)})
    active_host = active_suppressions(host_supps, today=today)

    summary = {
        "projects_count": len(projects),
        "posture_distribution": posture_dist,
        "quarantined": quarantined_list,
        "at_risk_running": at_risk,
        "active_suppressions_count": active_supps_count + len(active_host),
        "active_suppressions_projects": projects_with_supps,
        "active_suppressions_host": len(active_host),
        "host_suppressions": [
            {"cve_id": s.cve_id, "until": s.until.isoformat(), "reason": s.reason}
            for s in active_host
        ],
        "last_fleet_scan": max(last_scans) if last_scans else None,
        "grace": grace_payload,
        "held_by_breaker": _held_payload(paths),
    }
    if unreadable:
        summary["unreadable"] = unreadable
    return summary


def _report_unreadable(unreadable: list[dict], paths: BoxPaths) -> None:
    for entry in unreadable:
        # A null project is a box-wide file; its error names the file.
        source = entry["project"] or "box-wide file"
        print(f"ERROR: security: {source}: {entry['error']}", file=sys.stderr)
        log_error("security", f"fleet summary could not read {source}: {entry['error']}",
                  paths, project=entry["project"])


def _held_payload(paths: BoxPaths) -> dict:
    """Projects whose new quarantine the circuit breaker is holding."""
    try:
        held = read_held(paths)
    except BreakerError as e:
        return {"error": [str(e)]}
    return {name: sorted(cves) for name, cves in sorted(held.items())}


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
        registry = read_registry(paths)
        if not (registry.names or registry.problems):
            if as_json:
                print(format_fleet_json({
                    "projects_count": 0,
                    "posture_distribution": {
                        "relaxed": 0, "balanced": 0, "strict": 0, "paranoid": 0,
                    },
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
        summary = fleet_summary(paths)
        if as_json:
            print(format_fleet_json(summary))
        else:
            print(format_fleet_text(summary))
        if summary.get("unreadable"):
            _report_unreadable(summary["unreadable"], paths)
            sys.exit(1)
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
