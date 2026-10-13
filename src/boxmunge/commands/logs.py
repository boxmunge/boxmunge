"""boxmunge logs — view container, host, and boxmunge service logs.

Distinct from `boxmunge log` (the structured operational audit log). Use
`logs` for live container debugging, journalctl, and boxmunge service tail;
use `log` to query structured deploy/check/rollback events.
"""

import subprocess
import sys

from boxmunge.paths import BoxPaths
from boxmunge.docker import compose_logs, compose_logs_capture, DockerError


def cmd_logs(args: list[str]) -> None:
    """CLI entry point for logs command."""
    from boxmunge.commands.argv import (
        parse_args, require_project_name, usage_error,
    )
    if args in (["--host"], ["--boxmunge"]):
        paths = BoxPaths()
        if args == ["--host"]:
            _show_host_logs()
        else:
            _show_boxmunge_logs(paths)
        return
    if "--host" in args or "--boxmunge" in args:
        usage_error("logs", "--host and --boxmunge take no other arguments")

    parsed = parse_args(
        "logs", args, flags={"--follow"}, options={"--tail"},
        min_positional=1, max_positional=2,
    )
    project = require_project_name("logs", parsed.positional[0])
    service = parsed.positional[1] if len(parsed.positional) > 1 else None
    follow = parsed.has("--follow")
    tail = 100
    raw_tail = parsed.get("--tail")
    if raw_tail is not None:
        if not raw_tail.isdigit():
            usage_error("logs", f"--tail must be a whole number, got {raw_tail!r}")
        tail = int(raw_tail)

    paths = BoxPaths()
    project_dir = paths.project_dir(project)
    if not project_dir.exists():
        print(f"ERROR: Project not found: {project}", file=sys.stderr)
        sys.exit(1)

    compose_files = ["compose.yml"]
    override = paths.project_compose_override(project)
    if override.exists():
        compose_files.append("compose.boxmunge.yml")

    try:
        if follow:
            # Real-time streaming — pass through unchanged so terminal
            # users get immediate output as docker emits it.
            compose_logs(
                project_dir, service=service, tail=tail, follow=follow,
                compose_files=compose_files,
            )
            return
        # Non-follow: capture, print, then append a writable hint
        # postscript if read-only-fs errors are detected. The capture
        # delay is bounded by `--tail=N` and is imperceptible at the
        # default tail=100.
        output = compose_logs_capture(
            project_dir, service=service, tail=tail,
            compose_files=compose_files,
        )
        print(output, end="" if output.endswith("\n") else "\n")
        _append_writable_postscript(output)
    except DockerError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


def _append_writable_postscript(output: str) -> None:
    """Append a v0.9 writable-hint postscript when read-only-fs errors
    are visible in the captured log block. Stays silent on clean logs."""
    from boxmunge.writable_diagnostics import scan_logs
    errors = scan_logs(output)
    if not errors:
        return
    paths_list = ", ".join(repr(e.path) for e in errors)
    print(
        f"\n[HINT] Read-only filesystem errors detected for path(s) "
        f"{paths_list}.\n"
        f"       Declare the path(s) in manifest.yml under the "
        f"service's `writable.ephemeral`\n"
        f"       (or `writable.persistent` for data that should "
        f"survive restart). See: agent-help writable.",
        file=sys.stderr,
    )


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
