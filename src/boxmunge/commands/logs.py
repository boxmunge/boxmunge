"""boxmunge logs — view project, host, and operational logs."""

import subprocess
import sys

from boxmunge.paths import BoxPaths
from boxmunge.docker import compose_logs, DockerError


def cmd_logs(args: list[str]) -> None:
    """CLI entry point for logs command."""
    print("Note: 'logs' is deprecated. Use 'boxmunge log' instead.", file=sys.stderr)
    paths = BoxPaths()

    if "--host" in args:
        _show_host_logs()
        return

    if "--boxmunge" in args:
        _show_boxmunge_logs(paths)
        return

    if not args:
        print("Usage: boxmunge logs <project> [service] [--tail N] [--follow]",
              file=sys.stderr)
        print("       boxmunge logs --host", file=sys.stderr)
        print("       boxmunge logs --boxmunge", file=sys.stderr)
        sys.exit(2)

    project = args[0]

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    service = None
    tail = 100
    follow = False

    remaining = args[1:]
    positional_consumed = False
    i = 0
    while i < len(remaining):
        arg = remaining[i]
        if arg == "--tail" and i + 1 < len(remaining):
            tail = int(remaining[i + 1])
            i += 2
        elif arg == "--follow":
            follow = True
            i += 1
        elif not arg.startswith("--") and not positional_consumed:
            service = arg
            positional_consumed = True
            i += 1
        else:
            i += 1

    project_dir = paths.project_dir(project)
    if not project_dir.exists():
        print(f"ERROR: Project not found: {project}", file=sys.stderr)
        sys.exit(1)

    compose_files = ["compose.yml"]
    override = paths.project_compose_override(project)
    if override.exists():
        compose_files.append("compose.boxmunge.yml")

    try:
        compose_logs(project_dir, service=service, tail=tail, follow=follow,
                     compose_files=compose_files)
    except DockerError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


def _show_host_logs() -> None:
    """Show recent journal entries for boxmunge-related systemd units."""
    try:
        subprocess.run(
            ["journalctl", "-u", "boxmunge-*", "--no-pager", "-n", "100"],
            check=False,
        )
    except FileNotFoundError:
        print("journalctl not available (not on a systemd host?).", file=sys.stderr)
        sys.exit(1)


def _show_boxmunge_logs(paths: BoxPaths, tail: int = 100) -> None:
    """Show the boxmunge operational log (last N lines)."""
    log_file = paths.log_file
    if not log_file.exists():
        print("No operational log found yet.")
        return
    from collections import deque
    with log_file.open() as f:
        lines = deque(f, maxlen=tail)
    for line in lines:
        print(line, end="")
