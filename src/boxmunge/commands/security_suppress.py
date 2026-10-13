# SPDX-License-Identifier: Apache-2.0
"""boxmunge security suppress — record an operator-reviewed suppression.

Unsuppress lives in security_unsuppress.py; flag parsing and `--current`
target resolution in security_suppress_targets.py.
"""
from __future__ import annotations

import getpass
import os
import sys
from datetime import date, timedelta
from pathlib import Path

from boxmunge.commands.security_suppress_targets import (
    all_currently_quarantining_cves,
    current_quarantine_cves,
    drop_kev_listed,
    extract_flag,
    project_suppressions_path,
    utc_today,
)
from boxmunge.cve.suppressions import (
    MAX_SUPPRESSION_DAYS,
    SuppressionsError,
    add_suppression,
    find_recent_removal,
)
from boxmunge.log import log_error, log_operation
from boxmunge.paths import BoxPaths, validate_project_name
from boxmunge.project_registry import is_registered


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
    """boxmunge security suppress <CVE>|--current (--project <n>|--host) --until <d> --reason <t>.

    Two scopes. `--project` writes to the project's suppressions.yml
    (per-project scope). `--host` writes to /opt/boxmunge/config/suppressions.yml
    (applies across every project on the box — e.g. silencing base-image
    CVEs whose vulnerable code path no deployed service loads). Project
    entries win precedence over host entries on collision.

    `--current` suppresses every CVE currently at QUARANTINE disposition.
    With `--project P` that means findings for P; with `--host` it means
    the union of findings across every project on the box. Removes the
    need to copy-paste CVE ids.
    """
    from boxmunge.commands.argv import parse_args
    parse_args(  # reject unknown flags and stray positionals up front
        "security", args, flags={"--current", "--host"},
        options={"--project", "--until", "--reason"}, max_positional=1,
    )
    use_current = "--current" in args
    use_host = "--host" in args
    rest: list[str]
    cve_id_positional: str | None
    if use_current:
        cve_id_positional = None
        rest = [a for a in args if a != "--current"]
        # Reject the ambiguous form `suppress CVE-X --current ...` — the
        # operator must pick one or the other.
        if rest and not rest[0].startswith("--"):
            print(
                "ERROR: --current cannot be combined with a positional CVE id.",
                file=sys.stderr,
            )
            return 2
    else:
        if not args or args[0].startswith("--"):
            print(
                "Usage: boxmunge security suppress <CVE>|--current "
                "(--project <name>|--host) --until <YYYY-MM-DD> --reason <text>",
                file=sys.stderr,
            )
            return 2
        cve_id_positional = args[0]
        rest = args[1:]

    if use_host:
        rest = [a for a in rest if a != "--host"]
    project = extract_flag(rest, "--project")
    until_str = extract_flag(rest, "--until")
    reason = extract_flag(rest, "--reason")

    # Scope must be exactly one of --project or --host.
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

    missing = [
        n for n, v in [
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

    assert until_str is not None and reason is not None

    if use_host:
        # Host scope: no project to validate; suppressions_path is the
        # config-level file. The audit log writes use project="(host)" as
        # a sentinel so log queries can filter on it.
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
            cve_for_log = cve_id_positional or "-"
            print(
                f"ERROR: project '{project}' is not registered.",
                file=sys.stderr,
            )
            log_error(
                "cve-suppress",
                f"Suppression rejected: project '{project}' is not registered "
                f"({cve_for_log})",
                paths, project=project,
                detail={"cve_id": cve_for_log, "reason": "project_not_registered"},
            )
            return 1
        suppressions_path = project_suppressions_path(paths, project)
        log_project = project
        scope_label = f"project {project}"

    today = utc_today()
    # Use a sentinel CVE id in audit log lines for failures that happen
    # before per-CVE work begins (one entry covers --current and positional).
    cve_for_log = cve_id_positional or "(current)"
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
            f"{cve_for_log} in {project}",
            paths, project=project,
            detail={
                "cve_id": cve_for_log, "until_raw": until_str,
                "reason": "invalid_until_format",
            },
        )
        return 1
    if (until - today).days > MAX_SUPPRESSION_DAYS:
        latest = today + timedelta(days=MAX_SUPPRESSION_DAYS)
        print(
            f"ERROR: --until may be at most {MAX_SUPPRESSION_DAYS} days ahead "
            f"(latest {latest.isoformat()}, got {until.isoformat()}). Re-review "
            f"and extend the suppression when it expires.",
            file=sys.stderr,
        )
        log_error(
            "cve-suppress",
            f"Suppression rejected: --until {until.isoformat()} is more than "
            f"{MAX_SUPPRESSION_DAYS} days ahead for {cve_for_log} in {project}",
            paths, project=project,
            detail={
                "cve_id": cve_for_log, "until": until.isoformat(),
                "max_days": MAX_SUPPRESSION_DAYS, "reason": "until_too_far",
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
            f"the future for {cve_for_log} in {project}",
            paths, project=project,
            detail={
                "cve_id": cve_for_log, "until": until.isoformat(),
                "today": today.isoformat(), "reason": "until_not_future",
            },
        )
        return 1

    if not reason.strip():
        print("ERROR: --reason must be a non-empty string", file=sys.stderr)
        log_error(
            "cve-suppress",
            f"Suppression rejected: empty --reason for {cve_for_log} in "
            f"{project}",
            paths, project=project,
            detail={"cve_id": cve_for_log, "reason": "empty_reason"},
        )
        return 1

    try:
        reviewer = _resolve_reviewer()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error(
            "cve-suppress",
            f"Suppression rejected: reviewer unresolved for {cve_for_log} "
            f"in {project} ({e})",
            paths, project=project,
            detail={"cve_id": cve_for_log, "reason": "reviewer_unresolved"},
        )
        return 1

    # suppressions_path was set above per scope (--host vs --project).
    # Resolve the target CVE list. For --current, refuse if no QUARANTINE
    # findings exist — silently doing nothing would be the wrong UX
    # (operator expected suppressions to happen).
    if use_current:
        if use_host:
            cve_ids = all_currently_quarantining_cves(paths)
            if not cve_ids:
                print(
                    "ERROR: no current quarantine-level findings across any "
                    "project on this box. Run `security scan` first, or "
                    "specify a CVE id explicitly.",
                    file=sys.stderr,
                )
                log_error(
                    "cve-suppress",
                    "--current --host rejected: no QUARANTINE findings in "
                    "any project's scan_state",
                    paths, project=log_project,
                    detail={"reason": "no_current_quarantine_findings"},
                )
                return 1
            print(
                f"Suppressing {len(cve_ids)} current quarantine-level "
                f"finding{'s' if len(cve_ids) != 1 else ''} "
                f"(host-scoped, applies across all projects):"
            )
        else:
            assert project is not None
            findings = current_quarantine_cves(paths, project)
            if not findings:
                print(
                    f"ERROR: no current quarantine-level findings for "
                    f"'{project}'. Run `security scan {project}` first, or "
                    f"specify a CVE id explicitly.",
                    file=sys.stderr,
                )
                log_error(
                    "cve-suppress",
                    f"--current rejected: no QUARANTINE findings in scan_state "
                    f"for {project}",
                    paths, project=project,
                    detail={"reason": "no_current_quarantine_findings"},
                )
                return 1
            cve_ids = [f["cve_id"] for f in findings]
            print(
                f"Suppressing {len(cve_ids)} current quarantine-level "
                f"finding{'s' if len(cve_ids) != 1 else ''} for {project}:"
            )
    else:
        assert cve_id_positional is not None
        cve_ids = [cve_id_positional]

    cve_ids = drop_kev_listed(paths, cve_ids, positional=not use_current,
                               log_project=log_project)
    if not cve_ids:
        return 1

    for cve_id in cve_ids:
        rc = _apply_single_suppression(
            paths=paths,
            project=log_project,
            scope_label=scope_label,
            cve_id=cve_id,
            until=until,
            reason=reason,
            reviewer=reviewer,
            today=today,
            suppressions_path=suppressions_path,
        )
        if rc != 0:
            return rc
    return 0


def _apply_single_suppression(
    *,
    paths: BoxPaths,
    project: str,
    scope_label: str,
    cve_id: str,
    until: date,
    reason: str,
    reviewer: str,
    today: date,
    suppressions_path: Path,
) -> int:
    """Add one suppression entry. Returns 0 on success, 1 on failure.

    Extracted so the positional `<CVE>` path and the `--current` bulk path
    share the same per-CVE history check, add, audit log, and stdout
    summary. Caller has already validated until/reason/reviewer and the
    project gate.
    """
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
        _new_entry = add_suppression(
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

    log_detail["scope"] = scope_label
    print(f"Suppression added for {cve_id} ({scope_label})")
    print(f"  Until:        {until.isoformat()}")
    print(f"  Reason:       {reason}")
    print(f"  Reviewed by:  {reviewer}")
    return 0
