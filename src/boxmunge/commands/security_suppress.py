# SPDX-License-Identifier: Apache-2.0
"""boxmunge security suppress / unsuppress — operator suppression management."""
from __future__ import annotations

import getpass
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from boxmunge.cve.suppressions import (
    SuppressionsError,
    add_suppression,
    remove_suppression,
)
from boxmunge.paths import BoxPaths, validate_project_name
from boxmunge.project_registry import is_registered


def _project_suppressions_path(paths: BoxPaths, project: str) -> Path:
    return paths.project_dir(project) / "security" / "suppressions.yml"


def _extract_flag(args: list[str], flag: str) -> str | None:
    """Pull a `--flag value` pair out of args. Returns the value or None."""
    if flag not in args:
        return None
    i = args.index(flag)
    if i + 1 >= len(args):
        return None
    return args[i + 1]


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _resolve_reviewer() -> str:
    """Try $USER, then getpass.getuser(). Empty -> raise."""
    candidate = os.environ.get("USER", "").strip()
    if candidate:
        return candidate
    try:
        candidate = (getpass.getuser() or "").strip()
    except OSError:
        candidate = ""
    if not candidate:
        raise RuntimeError(
            "Could not determine reviewer (set $USER and try again)."
        )
    return candidate


def cmd_security_suppress(args: list[str], paths: BoxPaths) -> int:
    """boxmunge security suppress <CVE> --project <n> --until <d> --reason <t>."""
    if not args or args[0].startswith("--"):
        print(
            "Usage: boxmunge security suppress <CVE> --project <name> "
            "--until <YYYY-MM-DD> --reason <text>",
            file=sys.stderr,
        )
        return 2
    cve_id = args[0]
    rest = args[1:]
    project = _extract_flag(rest, "--project")
    until_str = _extract_flag(rest, "--until")
    reason = _extract_flag(rest, "--reason")

    missing = [
        n for n, v in [
            ("--project", project),
            ("--until", until_str),
            ("--reason", reason),
        ] if not v
    ]
    if missing:
        print(
            f"ERROR: missing required flag(s): {', '.join(missing)}",
            file=sys.stderr,
        )
        return 2

    assert project is not None and until_str is not None and reason is not None
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if not is_registered(project, paths):
        print(
            f"ERROR: project '{project}' is not registered.",
            file=sys.stderr,
        )
        return 1

    today = _today()
    try:
        until = date.fromisoformat(until_str)
    except ValueError:
        print(
            f"ERROR: --until must be YYYY-MM-DD, got {until_str!r}",
            file=sys.stderr,
        )
        return 1
    if until <= today:
        print(
            f"ERROR: --until must be a future date (got {until.isoformat()}, "
            f"today is {today.isoformat()})",
            file=sys.stderr,
        )
        return 1

    if not reason.strip():
        print("ERROR: --reason must be a non-empty string", file=sys.stderr)
        return 1

    try:
        reviewer = _resolve_reviewer()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    try:
        add_suppression(
            _project_suppressions_path(paths, project),
            cve_id=cve_id,
            until=until,
            reason=reason,
            reviewed_by=reviewer,
            today=today,
        )
    except SuppressionsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"Suppression added for {cve_id} in project {project}")
    print(f"  Until:        {until.isoformat()}")
    print(f"  Reason:       {reason}")
    print(f"  Reviewed by:  {reviewer}")
    return 0


def cmd_security_unsuppress(args: list[str], paths: BoxPaths) -> int:
    if not args or args[0].startswith("--"):
        print(
            "Usage: boxmunge security unsuppress <CVE> --project <name>",
            file=sys.stderr,
        )
        return 2
    cve_id = args[0]
    project = _extract_flag(args[1:], "--project")
    if not project:
        print("ERROR: missing required flag: --project", file=sys.stderr)
        return 2
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if not is_registered(project, paths):
        print(
            f"ERROR: project '{project}' is not registered.",
            file=sys.stderr,
        )
        return 1

    try:
        remove_suppression(
            _project_suppressions_path(paths, project), cve_id,
        )
    except SuppressionsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"Suppression removed for {cve_id} in project {project}")
    return 0
