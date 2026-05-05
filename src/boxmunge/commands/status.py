"""boxmunge status — dashboard view of all projects."""

import json
import sys
from datetime import datetime, timezone

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


def run_status(paths: BoxPaths, as_json: bool = False) -> int:
    """Show status dashboard for all projects."""
    projects_dir = paths.projects
    if not projects_dir.exists():
        print("No projects directory found.")
        return 0

    deployed = sorted(
        p.name for p in projects_dir.iterdir()
        if p.is_dir() and (p / "manifest.yml").exists()
    )
    pre_registered = sorted(
        p.name for p in projects_dir.iterdir()
        if p.is_dir() and not (p / "manifest.yml").exists()
    )

    if not deployed and not pre_registered:
        print("No projects registered.")
        return 0

    rows = []
    for name in deployed:
        if is_paused(name, paths):
            deploy = read_state(paths.project_deploy_state(name))
            deployed_at = deploy.get("deployed_at", "-")
            rows.append({
                "project": name,
                "status": "PAUSED",
                "last_check": "-",
                "deployed_at": deployed_at,
                "raw_status": "paused",
            })
            continue
        health = read_state(paths.project_health_state(name))
        deploy = read_state(paths.project_deploy_state(name))

        status = health.get("status", "unknown")
        last_check = health.get("last_check", "-")
        deployed_at = deploy.get("deployed_at", "-")

        if status == "ok":
            display_status = "OK"
        elif status == "critical_stopped":
            display_status = "CRITICAL (stopped)"
        elif status == "failing":
            display_status = "FAILING"
        else:
            display_status = status.upper()

        rows.append({
            "project": name,
            "status": display_status,
            "last_check": last_check,
            "deployed_at": deployed_at,
            "raw_status": status,
        })

    for name in pre_registered:
        rows.append({
            "project": name,
            "status": "PRE-REGISTERED",
            "last_check": "-",
            "deployed_at": "-",
            "raw_status": "pre-registered",
        })

    if as_json:
        # JSON output keeps full-precision timestamps for machine consumption.
        print(json.dumps(rows, indent=2))
    else:
        # Human-readable: trim timestamps to the second; widen STATUS to fit
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

    return 0


def cmd_status(args: list[str]) -> None:
    """CLI entry point for status command."""
    paths = BoxPaths()
    as_json = "--json" in args
    sys.exit(run_status(paths, as_json=as_json))
