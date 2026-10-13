# SPDX-License-Identifier: Apache-2.0
"""boxmunge security unsuppress — remove a suppression, keeping its history."""
from __future__ import annotations

import sys

from boxmunge.commands.security_suppress_targets import (
    extract_flag,
    project_suppressions_path,
    utc_today,
)
from boxmunge.cve.suppressions import (
    SuppressionsError,
    load_suppressions,
    record_removal,
    remove_suppression,
)
from boxmunge.log import log_error, log_operation
from boxmunge.paths import BoxPaths, validate_project_name
from boxmunge.project_registry import is_registered


def cmd_security_unsuppress(args: list[str], paths: BoxPaths) -> int:
    """boxmunge security unsuppress <CVE> (--project <name>|--host)."""
    from boxmunge.commands.argv import parse_args
    parse_args(  # reject unknown flags and stray positionals up front
        "security", args, flags={"--host"}, options={"--project"},
        max_positional=1,
    )
    if not args or args[0].startswith("--"):
        print(
            "Usage: boxmunge security unsuppress <CVE> "
            "(--project <name>|--host)",
            file=sys.stderr,
        )
        return 2
    cve_id = args[0]
    rest = args[1:]
    use_host = "--host" in rest
    if use_host:
        rest = [a for a in rest if a != "--host"]
    project = extract_flag(rest, "--project")

    if use_host and project is not None:
        print(
            "ERROR: --host and --project are mutually exclusive.",
            file=sys.stderr,
        )
        return 2
    if not use_host and project is None:
        print(
            "ERROR: missing required flag(s): one of --project, --host",
            file=sys.stderr,
        )
        return 2

    if use_host:
        suppressions_path = paths.host_suppressions
        log_project = "(host)"
        scope_label = "host"
    else:
        assert project is not None
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
        suppressions_path = project_suppressions_path(paths, project)
        log_project = project
        scope_label = f"project {project}"

    # Load the entry BEFORE removal so we can record it to history and
    # populate the audit log detail.
    try:
        existing = load_suppressions(suppressions_path)
    except SuppressionsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error(
            "cve-suppress",
            f"Unsuppress rejected: cannot load suppressions for "
            f"{scope_label} ({e})",
            paths, project=log_project,
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
            paths, project=log_project,
            detail={"cve_id": cve_id, "reason": "remove_failed"},
        )
        return 1

    today = utc_today()
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
            f"Suppression removed for {cve_id} from {scope_label}, BUT "
            f"history write failed: {e}",
            paths, project=log_project,
            detail={"cve_id": cve_id, "reason": "history_write_failed"},
        )
        return 1

    detail: dict[str, object] = {
        "cve_id": cve_id,
        "scope": scope_label,
        "previous_until": removed.until.isoformat(),
        "previous_added": removed.added.isoformat(),
    }
    if target is not None:
        detail["previous_reason"] = target.reason
        detail["previous_reviewed_by"] = target.reviewed_by
    log_operation(
        "cve-suppress",
        f"Suppression removed: {cve_id}",
        paths, project=log_project, detail=detail,
    )
    print(f"Suppression removed for {cve_id} ({scope_label})")
    return 0
