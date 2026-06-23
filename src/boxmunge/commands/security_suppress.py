# SPDX-License-Identifier: Apache-2.0
"""boxmunge security suppress / unsuppress — operator suppression management."""
from __future__ import annotations

import getpass
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.cve.policy import Disposition
from boxmunge.cve.scan_state import read_scan_state
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

# Severity rank for ordering --current suppression output (Critical first).
# Mirrors policy._SEVERITY_RANK but uses the stored string values from
# scan_state.json so we don't have to round-trip through the enum here.
_SEVERITY_RANK = {
    "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0,
}


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


def _current_quarantine_cves(
    paths: BoxPaths, project: str,
) -> list[dict[str, Any]]:
    """Return findings (deduped by CVE id) currently at QUARANTINE disposition.

    Reads scan_state for the project. Returns an empty list if no scan has
    run or no findings are at QUARANTINE disposition. Within a duplicate
    CVE id, the highest-severity entry wins (a CVE elevated in one image
    keeps that severity in the output). Result ordered Critical → Unknown,
    then by CVE id for stable display.
    """
    state = read_scan_state(paths.project_scan_state(project))
    if not state:
        return []
    seen: dict[str, dict[str, Any]] = {}
    for decision in state.get("decisions", []) or []:
        for f in decision.get("findings", []) or []:
            if f.get("disposition") != Disposition.QUARANTINE.value:
                continue
            cve = f.get("cve_id")
            if not cve:
                continue
            existing = seen.get(cve)
            rank_new = _SEVERITY_RANK.get(f.get("effective_severity"), 0)
            rank_old = _SEVERITY_RANK.get(
                existing.get("effective_severity") if existing else None, 0,
            )
            if existing is None or rank_new > rank_old:
                seen[cve] = f
    return sorted(
        seen.values(),
        key=lambda f: (
            -_SEVERITY_RANK.get(f.get("effective_severity"), 0),
            f.get("cve_id", ""),
        ),
    )


def _all_currently_quarantining_cves(paths: BoxPaths) -> list[str]:
    """Union of QUARANTINE-disposition CVE ids across every project on the box.

    Used by `--current --host` to suppress every CVE currently blocking any
    project in a single operation. Deduped by CVE id (a CVE quarantining
    multiple projects becomes one suppression). Order: severity rank
    descending, then CVE id ascending — matches per-project --current
    ordering for consistent operator UX.
    """
    if not paths.projects.exists():
        return []
    seen: dict[str, dict[str, Any]] = {}
    for proj_dir in sorted(paths.projects.iterdir()):
        if not proj_dir.is_dir() or not (proj_dir / "manifest.yml").exists():
            continue
        for f in _current_quarantine_cves(paths, proj_dir.name):
            cve = f["cve_id"]
            existing = seen.get(cve)
            sev_new = f.get("effective_severity") or ""
            sev_old = (
                existing.get("effective_severity") or "" if existing else ""
            )
            rank_new = _SEVERITY_RANK.get(sev_new, 0)
            rank_old = _SEVERITY_RANK.get(sev_old, 0)
            if existing is None or rank_new > rank_old:
                seen[cve] = f
    return [
        f["cve_id"]
        for f in sorted(
            seen.values(),
            key=lambda f: (
                -_SEVERITY_RANK.get(f.get("effective_severity") or "", 0),
                f.get("cve_id", ""),
            ),
        )
    ]


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
    project = _extract_flag(rest, "--project")
    until_str = _extract_flag(rest, "--until")
    reason = _extract_flag(rest, "--reason")

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
        suppressions_path = _project_suppressions_path(paths, project)
        log_project = project
        scope_label = f"project {project}"

    today = _today()
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
            cve_ids = _all_currently_quarantining_cves(paths)
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
            findings = _current_quarantine_cves(paths, project)
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


def cmd_security_unsuppress(args: list[str], paths: BoxPaths) -> int:
    """boxmunge security unsuppress <CVE> (--project <name>|--host)."""
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
    project = _extract_flag(rest, "--project")

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
        suppressions_path = _project_suppressions_path(paths, project)
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
