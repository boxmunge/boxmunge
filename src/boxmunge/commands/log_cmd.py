# SPDX-License-Identifier: Apache-2.0
"""boxmunge log — query structured operational logs with filtering."""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from boxmunge.paths import BoxPaths


def parse_log_file(path: Path) -> list[dict[str, Any]]:
    """Parse a JSON-lines log file. Skips malformed lines."""
    if not path.exists():
        return []
    entries = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def _parse_since(since: str) -> datetime:
    """Parse a duration string like '1h', '7d', '30m' into a cutoff datetime."""
    if not since:
        raise ValueError("Duration string must not be empty")
    unit = since[-1]
    try:
        value = int(since[:-1])
    except ValueError:
        raise ValueError(f"Invalid duration: {since!r} (expected e.g. '1h', '7d', '30m')")
    now = datetime.now(timezone.utc)
    if unit == "m":
        return now - timedelta(minutes=value)
    elif unit == "h":
        return now - timedelta(hours=value)
    elif unit == "d":
        return now - timedelta(days=value)
    raise ValueError(f"Unknown unit '{unit}' in duration '{since}' (use m/h/d)")


def filter_log_entries(
    entries: list[dict[str, Any]],
    project: str | None = None,
    component: str | None = None,
    level: str | None = None,
    since: str | None = None,
    tail: int | None = None,
) -> list[dict[str, Any]]:
    """Filter log entries by project, component, level, and time."""
    result = entries

    if project:
        result = [e for e in result if e.get("project") == project]
    if component:
        result = [e for e in result if e.get("component") == component]
    if level:
        result = [e for e in result if e.get("level") == level]
    if since:
        cutoff = _parse_since(since)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S")
        result = [e for e in result if e.get("ts", "") >= cutoff_str]
    if tail is not None:
        result = result[-tail:]

    return result


def _format_human(entry: dict[str, Any]) -> str:
    """Format a log entry for human reading."""
    ts = entry.get("ts", "")[:19]
    level = entry.get("level", "info").upper()
    component = entry.get("component", "")
    project = entry.get("project")
    msg = entry.get("msg", "")
    scope = f"{component}:{project}" if project else component
    return f"{ts} {level:5s} {scope} {msg}"


def run_log(
    paths: BoxPaths,
    *,
    project: str | None = None,
    component: str | None = None,
    level: str | None = None,
    since: str | None = None,
    tail: int | None = 50,
    as_json: bool = False,
    containers: bool = False,
) -> int:
    """Execute the log command. Returns 0 on success."""
    entries = parse_log_file(paths.log_file)
    filtered = filter_log_entries(entries, project=project, component=component,
                                  level=level, since=since, tail=tail)

    if not filtered:
        if not as_json:
            print("No log entries found.")
    else:
        for entry in filtered:
            if as_json:
                print(json.dumps(entry, default=str))
            else:
                print(_format_human(entry))

    if containers and project:
        from boxmunge.docker import compose_logs_capture, DockerError
        project_dir = paths.project_dir(project)
        if project_dir.exists():
            compose_files = ["compose.yml"]
            override = paths.project_compose_override(project)
            if override.exists():
                compose_files.append("compose.boxmunge.yml")
            try:
                docker_tail = 50 if tail is None else tail
                output = compose_logs_capture(project_dir, tail=docker_tail,
                                              compose_files=compose_files)
                if output:
                    print(f"\n--- Container logs for {project} ---")
                    print(output)
            except DockerError as e:
                print(f"WARN: Could not fetch container logs: {e}",
                      file=sys.stderr)

    return 0


def cmd_log(args: list[str]) -> None:
    """CLI entry point for log command."""
    from boxmunge.commands.argv import (
        parse_args, require_project_name, usage_error,
    )
    parsed = parse_args(
        "log", args,
        flags={"--json", "--all", "--containers"},
        options={"--project", "--component", "--level", "--since", "--tail"},
    )
    project = parsed.get("--project")
    if project is not None:
        require_project_name("log", project)
    since = parsed.get("--since")
    if since is not None:
        try:
            _parse_since(since)
        except ValueError as e:
            usage_error("log", str(e))
    tail: int | None = 50
    raw_tail = parsed.get("--tail")
    if raw_tail is not None:
        if parsed.has("--all"):
            usage_error("log", "--tail and --all are mutually exclusive")
        if not raw_tail.isdigit():
            usage_error("log", f"--tail must be a whole number, got {raw_tail!r}")
        tail = int(raw_tail)
    if parsed.has("--all"):
        tail = None

    paths = BoxPaths()
    sys.exit(run_log(
        paths, project=project, component=parsed.get("--component"),
        level=parsed.get("--level"), since=since, tail=tail,
        as_json=parsed.has("--json"), containers=parsed.has("--containers"),
    ))
