"""boxmunge logs — view container, host, and boxmunge service logs.

Distinct from `boxmunge log` (the structured operational audit log). Use
`logs` for live container debugging, journalctl, and boxmunge service tail;
use `log` to query structured deploy/check/rollback events.
"""

import subprocess
import sys

from boxmunge.docker import (
    DockerError, compose_logs, compose_logs_capture,
)
from boxmunge.fs_nofollow import read_text_nofollow
from boxmunge.paths import (
    STAGING_SUFFIX, BoxPaths, InvalidProjectName, validate_project_name,
)
from boxmunge.staged_release import (
    ComposeTarget, has_slot, refuse_planted, staging_target,
)


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
            try:
                _show_boxmunge_logs(paths)
            except (OSError, UnicodeDecodeError) as e:
                print(f"ERROR: cannot read the operational log: {e}", file=sys.stderr)
                sys.exit(1)
        return
    if "--host" in args or "--boxmunge" in args:
        usage_error("logs", "--host and --boxmunge take no other arguments")

    parsed = parse_args(
        "logs", args, flags={"--follow", "--staging"}, options={"--tail"},
        min_positional=1, max_positional=2,
    )
    name = parsed.positional[0]
    paths = BoxPaths()
    # `<p>-staging` is staging's compose project, unless a legacy project
    # dir has that name: it gets the rename hint from the name check below.
    # The disk is consulted only for a valid <p>, never a path.
    base = name[:-len(STAGING_SUFFIX)] if name.endswith(STAGING_SUFFIX) else None
    if base is not None and _valid_name(base) and not (paths.projects / name).is_dir():
        usage_error("logs", f"staging runs as '{name}'; read its logs with: "
                            f"logs {base} --staging")
    project = require_project_name("logs", name)
    service = parsed.positional[1] if len(parsed.positional) > 1 else None
    follow = parsed.has("--follow")
    tail = 100
    raw_tail = parsed.get("--tail")
    if raw_tail is not None:
        if not raw_tail.isdigit():
            usage_error("logs", f"--tail must be a whole number, got {raw_tail!r}")
        tail = int(raw_tail)

    if not paths.project_dir(project).exists():
        print(f"ERROR: Project not found: {project}", file=sys.stderr)
        sys.exit(1)
    try:
        target = (_staging_target(paths, project) if parsed.has("--staging")
                  else _production_target(paths, project))
    except (NothingStaged, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        if follow:
            # Real-time streaming — pass through unchanged so terminal
            # users get immediate output as docker emits it.
            compose_logs(target.cwd, service=service, tail=tail, follow=follow,
                         **target.kwargs())
            return
        # Non-follow: capture, print, then append a writable hint
        # postscript if read-only-fs errors are detected. The capture
        # delay is bounded by `--tail=N` and is imperceptible at the
        # default tail=100.
        output = compose_logs_capture(target.cwd, service=service, tail=tail,
                                      **target.kwargs())
        print(output, end="" if output.endswith("\n") else "\n")
        _append_writable_postscript(output)
    except DockerError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


def _valid_name(name: str) -> bool:
    try:
        validate_project_name(name)
    except InvalidProjectName:
        return False
    return True


class NothingStaged(Exception):
    """`logs --staging` for a project with no staged release."""


def _production_target(paths: BoxPaths, project: str) -> ComposeTarget:
    files = ["compose.yml"]
    if paths.project_compose_override(project).exists():
        files.append("compose.boxmunge.yml")
    return ComposeTarget(cwd=paths.project_dir(project), project_name=project, files=files)


def _staging_target(paths: BoxPaths, project: str) -> ComposeTarget:
    """Staging's compose project as it runs, from the slot. Raises OSError
    for a link planted where the slot belongs, NothingStaged when there is
    none."""
    if has_slot(paths, project):
        refuse_planted(paths, project)
        return staging_target(paths, project)
    raise NothingStaged(f"'{project}' has no staged release. Stage one with "
                        f"'stage {project}', or read production's logs with "
                        f"'logs {project}'.")


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
    """Show the boxmunge operational log (last N lines, across rotation).
    logs/ is deploy-writable: a link, a FIFO or a huge file where a log should
    be raises OSError, naming it."""
    from boxmunge.log_rotation import log_files
    files = log_files(paths.log_file)
    if not files:
        print("No operational log found yet.")
        return
    lines: list[str] = []
    for path in reversed(files):
        lines = read_text_nofollow(path).splitlines(keepends=True) + lines
        if len(lines) >= tail:
            break
    for line in lines[len(lines) - tail:]:
        print(line, end="")
