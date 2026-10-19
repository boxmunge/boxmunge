"""boxmunge status — dashboard view of all projects."""

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from boxmunge.commands.argv import parse_args
from boxmunge.commands.health_state import MONITOR_STOPPED
from boxmunge.cve.quarantine import (
    checked_quarantine_record, is_quarantined, read_quarantine_state,
)
from boxmunge.fleet import PROJECT_INPUT_ERRORS, report_project_failure
from boxmunge.paths import BoxPaths
from boxmunge.pause import is_paused, pause_incomplete
from boxmunge.state import StateError, read_state


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


# Health states the health checks write; a missing state is "unknown".
HEALTH_STATES = ("ok", "failing", MONITOR_STOPPED, "unknown")
# Every value a row's "state" takes.
ROW_STATES = (*HEALTH_STATES, "quarantined", "paused", "pause_incomplete",
              "pre_registered", "error")
_LABELS = {"ok": "OK", MONITOR_STOPPED: "CRITICAL (stopped)", "failing": "FAILING",
           "unknown": "UNKNOWN", "quarantined": "QUARANTINED", "paused": "PAUSED",
           "pause_incomplete": "PAUSED (incomplete)",
           "pre_registered": "PRE-REGISTERED", "error": "ERROR"}


@dataclass
class StatusSnapshot:
    """Every project's dashboard row, and the projects that could not be read.

    Rows hold machine values: "state" is one of ROW_STATES, timestamps are
    as stored or None when absent, "quarantine" and "error" are None unless
    they apply. display_rows() turns them into what `status` prints.
    """

    projects_dir_exists: bool
    rows: list[dict[str, Any]] = field(default_factory=list)
    failures: list[tuple[str, Exception]] = field(default_factory=list)


def _row(name: str, state: str, *, last_check: str | None = None,
         deployed_at: str | None = None, quarantine: dict[str, str] | None = None,
         error: str | None = None) -> dict[str, Any]:
    return {"project": name, "state": state, "last_check": last_check,
            "deployed_at": deployed_at, "quarantine": quarantine, "error": error}


def collect_status(paths: BoxPaths) -> StatusSnapshot:
    """Build the dashboard rows without printing anything.

    A project whose state files cannot be read gets an "error" row and an
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
            snapshot.rows.append(_row(name, "error", error=f"{name}: {e}"))

    for name in pre_registered:
        snapshot.rows.append(_row(name, "pre_registered"))
    return snapshot


def display_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    """The rows as `status` and `status --json` print them: display labels,
    "-" for an absent value, and raw_status alongside."""
    shown = []
    for row in rows:
        state = row["state"]
        item = {
            "project": row["project"],
            "status": _LABELS[state],
            "last_check": row["last_check"] or "-",
            "deployed_at": row["deployed_at"] or "-",
            "raw_status": "pre-registered" if state == "pre_registered" else state,
        }
        if row["quarantine"] is not None:
            item.update(row["quarantine"])
        if row["error"] is not None:
            item["error"] = row["error"]
        shown.append(item)
    return shown


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

    rows = display_rows(snapshot.rows)
    if as_json:
        # JSON output keeps full-precision timestamps for machine consumption.
        print(json.dumps(rows, indent=2))
    else:
        _print_table(rows)

    return 1 if snapshot.failures else 0


def _project_row(name: str, paths: BoxPaths) -> dict[str, Any]:
    """Build one deployed project's dashboard row from its state files."""
    deploy = read_state(paths.project_deploy_state(name))
    deployed_at = deploy.get("deployed_at")
    # Quarantine takes precedence over pause if both markers exist
    # (mirrors lifecycle.is_blocked ordering — the security action is
    # the more specific one).
    if is_quarantined(name, paths):
        qstate = checked_quarantine_record(
            read_quarantine_state(name, paths), paths.project_quarantine_state(name))
        return _row(name, "quarantined", deployed_at=deployed_at, quarantine={
            "cve_id": qstate["cve_id"],
            "severity": qstate["effective_severity"] or qstate["severity"],
            "explanation": qstate["explanation"],
            "quarantined_at": qstate["quarantined_at"],
        })
    if is_paused(name, paths):
        state = "pause_incomplete" if pause_incomplete(name, paths) else "paused"
        return _row(name, state, deployed_at=deployed_at)
    health = read_state(paths.project_health_state(name))
    state = health.get("status", "unknown")
    if state not in HEALTH_STATES:
        raise StateError(f"Health state {paths.project_health_state(name)} has the status "
                         f"{state!r}; boxmunge writes one of {', '.join(HEALTH_STATES)}")
    return _row(name, state, last_check=health.get("last_check"), deployed_at=deployed_at)


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
            print(f"    lift with: a deploy of a fixed release, or security resume "
                  f"{row['project']}")


def cmd_status(args: list[str]) -> None:
    """CLI entry point for status command."""
    as_json = parse_args("status", args, flags={"--json"}).has("--json")
    paths = BoxPaths()
    sys.exit(run_status(paths, as_json=as_json))
