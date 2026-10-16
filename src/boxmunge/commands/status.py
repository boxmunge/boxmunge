"""boxmunge status — dashboard view of all projects."""

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

from boxmunge.commands.argv import parse_args
from boxmunge.cve.quarantine import is_quarantined, read_quarantine_state
from boxmunge.fleet import PROJECT_INPUT_ERRORS, report_project_failure
from boxmunge.paths import BoxPaths
from boxmunge.pause import is_paused
from boxmunge.state import read_state


def _short_ts(raw: str) -> str:
    """Trim an ISO timestamp to 'YYYY-MM-DD HH:MM:SS' (UTC). Pass-through on parse failure."""
    if not raw or raw == "-":
        return "-"
    # Normalize trailing Z so fromisoformat works on Python <3.11
    iso = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    try:
        ts = datetime.fromisoformat(iso)
    except ValueError:
        return raw[:19]
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc)
    return ts.strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class StatusSnapshot:
    """Every project's dashboard row, and the projects that could not be read."""

    projects_dir_exists: bool
    rows: list[dict[str, str]] = field(default_factory=list)
    failures: list[tuple[str, Exception]] = field(default_factory=list)


def collect_status(paths: BoxPaths) -> StatusSnapshot:
    """Build the dashboard rows without printing anything.

    A project whose state files cannot be read gets an ERROR row and an
    entry in ``failures``; the other rows are still built.
    """
    projects_dir = paths.projects
    if not projects_dir.exists():
        return StatusSnapshot(projects_dir_exists=False)

    deployed = sorted(
        p.name for p in projects_dir.iterdir()
        if p.is_dir() and (p / "manifest.yml").exists()
    )
    pre_registered = sorted(
        p.name for p in projects_dir.iterdir()
        if p.is_dir() and not (p / "manifest.yml").exists()
    )

    snapshot = StatusSnapshot(projects_dir_exists=True)
    for name in deployed:
        try:
            snapshot.rows.append(_project_row(name, paths))
        except PROJECT_INPUT_ERRORS as e:
            snapshot.failures.append((name, e))
            snapshot.rows.append({
                "project": name,
                "status": "ERROR",
                "last_check": "-",
                "deployed_at": "-",
                "raw_status": "error",
                "error": f"{name}: {e}",
            })

    for name in pre_registered:
        snapshot.rows.append({
            "project": name,
            "status": "PRE-REGISTERED",
            "last_check": "-",
            "deployed_at": "-",
            "raw_status": "pre-registered",
        })
    return snapshot


def run_status(paths: BoxPaths, as_json: bool = False) -> int:
    """Show status dashboard for all projects.

    A project whose state files cannot be read gets an ERROR row (and an
    ERROR line on stderr); the rest of the dashboard still renders. Returns
    1 if any project failed, else 0.
    """
    snapshot = collect_status(paths)
    if not snapshot.projects_dir_exists:
        print("No projects directory found.")
        return 0
    if not snapshot.rows:
        print("No projects registered.")
        return 0

    for name, error in snapshot.failures:
        report_project_failure("status", name, error, paths)

    if as_json:
        # JSON output keeps full-precision timestamps for machine consumption.
        print(json.dumps(snapshot.rows, indent=2))
    else:
        _print_table(snapshot.rows)

    return 1 if snapshot.failures else 0


def _project_row(name: str, paths: BoxPaths) -> dict[str, str]:
    """Build one deployed project's dashboard row from its state files."""
    # Quarantine takes precedence over pause if both markers exist
    # (mirrors lifecycle.is_blocked ordering — the security action is
    # the more specific one).
    if is_quarantined(name, paths):
        qstate = read_quarantine_state(name, paths) or {}
        deploy = read_state(paths.project_deploy_state(name))
        return {
            "project": name,
            "status": "QUARANTINED",
            "last_check": "-",
            "deployed_at": deploy.get("deployed_at", "-"),
            "raw_status": "quarantined",
            "cve_id": qstate.get("cve_id", "-"),
            "severity": (
                qstate.get("effective_severity")
                or qstate.get("severity", "-")
            ),
            "explanation": qstate.get("explanation", ""),
            "quarantined_at": qstate.get("quarantined_at", "-"),
        }
    if is_paused(name, paths):
        deploy = read_state(paths.project_deploy_state(name))
        return {
            "project": name,
            "status": "PAUSED",
            "last_check": "-",
            "deployed_at": deploy.get("deployed_at", "-"),
            "raw_status": "paused",
        }
    health = read_state(paths.project_health_state(name))
    deploy = read_state(paths.project_deploy_state(name))

    status = health.get("status", "unknown")
    if status == "ok":
        display_status = "OK"
    elif status == "critical_stopped":
        display_status = "CRITICAL (stopped)"
    elif status == "failing":
        display_status = "FAILING"
    else:
        display_status = status.upper()

    return {
        "project": name,
        "status": display_status,
        "last_check": health.get("last_check", "-"),
        "deployed_at": deploy.get("deployed_at", "-"),
        "raw_status": status,
    }


def _print_table(rows: list[dict[str, str]]) -> None:
    """Human-readable dashboard."""
    # Trim timestamps to the second; widen STATUS to fit
    # "CRITICAL (stopped)" (18 chars) and "PRE-REGISTERED" (14 chars).
    col_project = 25
    col_status = 20
    col_ts = 19  # "YYYY-MM-DD HH:MM:SS"
    header = (
        f"{'PROJECT':<{col_project}} "
        f"{'STATUS':<{col_status}} "
        f"{'LAST CHECK (UTC)':<{col_ts}} "
        f"{'DEPLOYED (UTC)':<{col_ts}}"
    )
    print(header)
    print(
        f"{'-'*col_project} {'-'*col_status} "
        f"{'-'*col_ts} {'-'*col_ts}"
    )
    for row in rows:
        print(
            f"{row['project']:<{col_project}} "
            f"{row['status']:<{col_status}} "
            f"{_short_ts(row['last_check']):<{col_ts}} "
            f"{_short_ts(row['deployed_at']):<{col_ts}}"
        )

    # Rationale block — a quarantine without its CVE rationale is
    # actionably useless. Surface CVE id, severity, and explanation
    # directly so operators don't have to round-trip through
    # `security <project>` to find out why a site is offline.
    quarantined = [r for r in rows if r["raw_status"] == "quarantined"]
    if quarantined:
        print()
        print("Quarantined projects:")
        for row in quarantined:
            cve = row.get("cve_id", "-")
            sev = row.get("severity", "-")
            explanation = row.get("explanation", "") or ""
            since = _short_ts(row.get("quarantined_at", "-"))
            print(f"  {row['project']}: {cve} {sev} (since {since} UTC)")
            if explanation:
                print(f"    reason: {explanation}")
            print(f"    lift with: security resume {row['project']}")


def cmd_status(args: list[str]) -> None:
    """CLI entry point for status command."""
    as_json = parse_args("status", args, flags={"--json"}).has("--json")
    paths = BoxPaths()
    sys.exit(run_status(paths, as_json=as_json))
