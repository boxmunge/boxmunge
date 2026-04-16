"""boxmunge status — dashboard view of all projects."""

import json
import sys
from datetime import datetime, timezone

from boxmunge.paths import BoxPaths
from boxmunge.state import read_state


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
        print(json.dumps(rows, indent=2))
    else:
        print(f"{'PROJECT':<25} {'STATUS':<22} {'LAST CHECK':<22} {'DEPLOYED'}")
        print(f"{'-'*25} {'-'*22} {'-'*22} {'-'*22}")
        for row in rows:
            print(
                f"{row['project']:<25} {row['status']:<22} "
                f"{row['last_check']:<22} {row['deployed_at']}"
            )

    return 0


def cmd_status(args: list[str]) -> None:
    """CLI entry point for status command."""
    paths = BoxPaths()
    as_json = "--json" in args
    sys.exit(run_status(paths, as_json=as_json))
