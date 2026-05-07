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
    find_recent_removal,
    load_suppressions,
    record_removal,
    remove_suppression,
)
from boxmunge.log import log_error, log_operation
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
        log_error(
            "cve-suppress",
            f"Suppression rejected: project '{project}' is not registered "
            f"({cve_id})",
            paths, project=project,
            detail={"cve_id": cve_id, "reason": "project_not_registered"},
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
        log_error(
            "cve-suppress",
            f"Suppression rejected: invalid --until {until_str!r} for "
            f"{cve_id} in {project}",
            paths, project=project,
            detail={
                "cve_id": cve_id, "until_raw": until_str,
                "reason": "invalid_until_format",
            },
        )
        return 1
    if until <= today:
        print(
            f"ERROR: --until must be a future date (got {until.isoformat()}, "
            f"today is {today.isoformat()})",
            file=sys.stderr,
        )
        log_error(
            "cve-suppress",
            f"Suppression rejected: --until {until.isoformat()} is not in "
            f"the future for {cve_id} in {project}",
            paths, project=project,
            detail={
                "cve_id": cve_id, "until": until.isoformat(),
                "today": today.isoformat(), "reason": "until_not_future",
            },
        )
        return 1

    if not reason.strip():
        print("ERROR: --reason must be a non-empty string", file=sys.stderr)
        log_error(
            "cve-suppress",
            f"Suppression rejected: empty --reason for {cve_id} in {project}",
            paths, project=project,
            detail={"cve_id": cve_id, "reason": "empty_reason"},
        )
        return 1

    try:
        reviewer = _resolve_reviewer()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error(
            "cve-suppress",
            f"Suppression rejected: reviewer unresolved for {cve_id} in "
            f"{project} ({e})",
            paths, project=project,
            detail={"cve_id": cve_id, "reason": "reviewer_unresolved"},
        )
        return 1

    suppressions_path = _project_suppressions_path(paths, project)

    # D-2: detect silent extensions. If this CVE was unsuppressed in the
    # last 7 days for this project, flag the re-suppression so the audit
    # trail makes the extension visible.
    try:
        recent = find_recent_removal(
            suppressions_path, cve_id, today=today,
        )
    except SuppressionsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error(
            "cve-suppress",
            f"Suppression rejected: history file unreadable for {cve_id} "
            f"in {project} ({e})",
            paths, project=project,
            detail={"cve_id": cve_id, "reason": "history_unreadable"},
        )
        return 1

    try:
        new_entry = add_suppression(
            suppressions_path,
            cve_id=cve_id,
            until=until,
            reason=reason,
            reviewed_by=reviewer,
            today=today,
        )
    except SuppressionsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error(
            "cve-suppress",
            f"Suppression rejected: {e}",
            paths, project=project,
            detail={"cve_id": cve_id, "reason": "validation_failed"},
        )
        return 1

    log_detail: dict[str, object] = {
        "cve_id": cve_id,
        "until": until.isoformat(),
        "reason": reason,
        "reviewed_by": reviewer,
        "previously_suppressed": recent is not None,
    }
    if recent is not None:
        days_ago = (today - recent.removed_at).days
        log_detail.update({
            "previous_until": recent.previous_until.isoformat(),
            "previous_added": recent.previous_added.isoformat(),
            "removed_at": recent.removed_at.isoformat(),
            "previous_reason": recent.previous_reason,
            "previous_reviewed_by": recent.previous_reviewed_by,
        })
        print(
            f"NOTE: {cve_id} was unsuppressed {days_ago} day"
            f"{'s' if days_ago != 1 else ''} ago and is being re-suppressed. "
            f"Original add date: {recent.previous_added.isoformat()}. "
            f"Verify the new reason reflects current state.",
            file=sys.stderr,
        )

    log_operation(
        "cve-suppress",
        f"Suppression added: {cve_id} until {until.isoformat()} "
        f"({reason})",
        paths, project=project,
        detail=log_detail,
    )

    print(f"Suppression added for {cve_id} in project {project}")
    print(f"  Until:        {until.isoformat()}")
    print(f"  Reason:       {reason}")
    print(f"  Reviewed by:  {reviewer}")
    # ``new_entry`` is the freshly-added Suppression — kept for symmetry
    # with cmd_security_unsuppress (and silences "unused variable" lint).
    _ = new_entry
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
        log_error(
            "cve-suppress",
            f"Unsuppress rejected: project '{project}' is not registered "
            f"({cve_id})",
            paths, project=project,
            detail={"cve_id": cve_id, "reason": "project_not_registered"},
        )
        return 1

    suppressions_path = _project_suppressions_path(paths, project)

    # Load the entry BEFORE removal so we can record it to history and
    # populate the audit log detail.
    try:
        existing = load_suppressions(suppressions_path)
    except SuppressionsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error(
            "cve-suppress",
            f"Unsuppress rejected: cannot load suppressions for {project} "
            f"({e})",
            paths, project=project,
            detail={"cve_id": cve_id, "reason": "load_failed"},
        )
        return 1
    target = next((s for s in existing if s.cve_id == cve_id), None)

    try:
        removed = remove_suppression(suppressions_path, cve_id)
    except SuppressionsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error(
            "cve-suppress",
            f"Unsuppress rejected: {e}",
            paths, project=project,
            detail={"cve_id": cve_id, "reason": "remove_failed"},
        )
        return 1

    today = _today()
    try:
        record_removal(suppressions_path, prior=removed, removed_at=today)
    except (SuppressionsError, OSError) as e:
        # History write failure is loud: an unsuppress whose history
        # didn't persist breaks the silent-extension detector. Surface
        # it (the active list was already updated on disk).
        print(
            f"ERROR: suppression removed but history write failed: {e}",
            file=sys.stderr,
        )
        log_error(
            "cve-suppress",
            f"Suppression removed for {cve_id} in {project}, BUT history "
            f"write failed: {e}",
            paths, project=project,
            detail={"cve_id": cve_id, "reason": "history_write_failed"},
        )
        return 1

    detail: dict[str, object] = {
        "cve_id": cve_id,
        "previous_until": removed.until.isoformat(),
        "previous_added": removed.added.isoformat(),
    }
    if target is not None:
        detail["previous_reason"] = target.reason
        detail["previous_reviewed_by"] = target.reviewed_by
    log_operation(
        "cve-suppress",
        f"Suppression removed: {cve_id}",
        paths, project=project, detail=detail,
    )
    print(f"Suppression removed for {cve_id} in project {project}")
    return 0
