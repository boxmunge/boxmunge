# SPDX-License-Identifier: Apache-2.0
"""MCP tool wrapper functions — each wraps an existing boxmunge CLI command.

These are consumed by mcp_server.py which registers them as MCP tools.
"""

import io
from contextlib import redirect_stdout
from typing import Any, Callable

from boxmunge.paths import BoxPaths


def capture_tool_call(
    func: Callable[[], int],
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a function, capturing its stdout and exit code.

    Returns a standardised result dict:
    {
        "success": bool,
        "exit_code": int,
        "data": dict,
        "messages": list[str],
    }
    """
    captured = io.StringIO()
    try:
        with redirect_stdout(captured):
            exit_code = func()
    except Exception as e:
        return {
            "success": False,
            "exit_code": 1,
            "data": data or {},
            "messages": captured.getvalue().splitlines() + [f"ERROR: {e}"],
        }

    return {
        "success": exit_code == 0,
        "exit_code": exit_code,
        "data": data or {},
        "messages": captured.getvalue().splitlines(),
    }


# ---------------------------------------------------------------------------
# Lazy BoxPaths singleton
# ---------------------------------------------------------------------------

_paths: BoxPaths | None = None


def _get_paths() -> BoxPaths:
    global _paths
    if _paths is None:
        _paths = BoxPaths()
    return _paths


# ---------------------------------------------------------------------------
# Tool functions — each wraps an existing run_* / cmd_* function
# ---------------------------------------------------------------------------

def _tool_deploy(project: str, ref: str | None = None,
                 no_snapshot: bool = False, dry_run: bool = False) -> dict:
    from boxmunge.commands.deploy import run_deploy
    paths = _get_paths()
    return capture_tool_call(
        lambda: run_deploy(project, paths, ref=ref,
                           no_snapshot=no_snapshot, dry_run=dry_run))


def _tool_stage(project: str, ref: str | None = None,
                dry_run: bool = False) -> dict:
    from boxmunge.commands.stage_cmd import run_stage
    paths = _get_paths()
    return capture_tool_call(
        lambda: run_stage(project, paths, ref=ref, dry_run=dry_run))


def _tool_promote(project: str, dry_run: bool = False) -> dict:
    from boxmunge.commands.promote_cmd import run_promote
    paths = _get_paths()
    return capture_tool_call(
        lambda: run_promote(project, paths, dry_run=dry_run))


def _tool_unstage(project: str, dry_run: bool = False) -> dict:
    from boxmunge.commands.unstage_cmd import run_unstage
    paths = _get_paths()
    return capture_tool_call(
        lambda: run_unstage(project, paths, dry_run=dry_run))


def _tool_rollback(project: str) -> dict:
    from boxmunge.commands.rollback import run_rollback
    paths = _get_paths()
    return capture_tool_call(
        lambda: run_rollback(project, paths, yes=True))


def _tool_check(project: str, verbose: bool = True) -> dict:
    from boxmunge.commands.check import run_check
    paths = _get_paths()
    return capture_tool_call(
        lambda: run_check(project, paths, verbose=verbose))


def _tool_backup(project: str) -> dict:
    from boxmunge.commands.backup_cmd import run_backup
    paths = _get_paths()
    return capture_tool_call(lambda: run_backup(project, paths))


def _tool_restore(project: str, snapshot: str | None = None) -> dict:
    from boxmunge.commands.restore import run_restore
    paths = _get_paths()
    return capture_tool_call(
        lambda: run_restore(project, paths, snapshot=snapshot, yes=True))


def _tool_validate(project: str) -> dict:
    from boxmunge.commands.validate import run_validate
    paths = _get_paths()
    return capture_tool_call(lambda: run_validate(project, paths))


def _tool_list_projects() -> dict:
    from boxmunge.commands.list_projects import run_list_projects
    paths = _get_paths()
    return capture_tool_call(lambda: run_list_projects(paths))


def _tool_secrets(args: list[str]) -> dict:
    from boxmunge.commands.secrets_cmd import run_secrets
    paths = _get_paths()
    return capture_tool_call(lambda: run_secrets(args, paths))


def _tool_upgrade(skip_self_test: bool = False) -> dict:
    from boxmunge.commands.upgrade_cmd import run_upgrade
    paths = _get_paths()
    return capture_tool_call(
        lambda: run_upgrade(paths, skip_self_test=skip_self_test))


def _tool_self_test(as_json: bool = False) -> dict:
    from boxmunge.commands.self_test_cmd import run_self_test
    paths = _get_paths()
    return capture_tool_call(
        lambda: run_self_test(paths, as_json=as_json))


# --- Health: structured data ---

def _run_health_checks(paths: BoxPaths) -> tuple[int, dict]:
    """Run all health checks, return (exit_code, data_dict)."""
    from boxmunge.commands.health_cmd import (
        HealthReport,
        check_age_key,
        check_caddy_container,
        check_config_drift,
        check_docker_running,
        check_file_permissions,
        check_project_containers,
        check_recent_errors,
        check_system_container,
    )
    report = HealthReport()
    report.checks.append(check_docker_running())
    report.checks.append(check_caddy_container())
    report.checks.append(check_system_container())
    report.checks.append(check_file_permissions(paths))
    report.checks.append(check_age_key(paths))
    report.checks.append(check_project_containers(paths))
    report.checks.append(check_config_drift(paths))
    report.checks.append(check_recent_errors(paths))

    from boxmunge.health_checks.hardening import (
        check_aide_status,
        check_auditd,
        check_crowdsec,
        check_sysctl_hardening,
        check_systemd_timers,
        check_ufw,
        check_unattended_upgrades,
    )
    try:
        from boxmunge.config import load_config
        config = load_config(paths)
        ssh_port = config.get("ssh_port", 922)
    except Exception:
        ssh_port = 922

    report.checks.append(check_ufw(ssh_port=ssh_port))
    report.checks.append(check_crowdsec())
    report.checks.append(check_aide_status())
    report.checks.append(check_auditd())
    report.checks.append(check_unattended_upgrades())
    report.checks.append(check_sysctl_hardening())
    report.checks.append(check_systemd_timers())

    data = {
        "healthy": report.exit_code == 0,
        "checks": [
            {"name": c.name, "status": c.status, "detail": c.detail}
            for c in report.checks
        ],
    }
    return report.exit_code, data


def _tool_health() -> dict:
    paths = _get_paths()
    exit_code, data = _run_health_checks(paths)
    return {
        "success": exit_code == 0,
        "exit_code": exit_code,
        "data": data,
        "messages": [],
    }


# --- Log: structured data ---

def _tool_log(project: str | None = None, component: str | None = None,
              level: str | None = None, since: str | None = None,
              tail: int = 50) -> dict:
    from boxmunge.commands.log_cmd import parse_log_file, filter_log_entries
    paths = _get_paths()
    entries = parse_log_file(paths.log_file)
    filtered = filter_log_entries(
        entries, project=project, component=component,
        level=level, since=since, tail=tail)
    return {
        "success": True,
        "exit_code": 0,
        "data": {"entries": filtered},
        "messages": [],
    }


# --- cmd_* wrappers (catch SystemExit) ---

def _tool_status() -> dict:
    from boxmunge.commands.status import cmd_status

    def wrapper() -> int:
        try:
            cmd_status(["--json"])
            return 0
        except SystemExit as e:
            return e.code or 0
    return capture_tool_call(wrapper)


def _tool_inbox(project: str | None = None) -> dict:
    from boxmunge.commands.inbox_cmd import cmd_inbox

    def wrapper() -> int:
        args = [project] if project else []
        try:
            cmd_inbox(args)
            return 0
        except SystemExit as e:
            return e.code or 0
    return capture_tool_call(wrapper)


def _tool_agent_help(topic: str | None = None) -> dict:
    from boxmunge.commands.help import cmd_agent_help

    def wrapper() -> int:
        args = [topic] if topic else []
        try:
            cmd_agent_help(args)
            return 0
        except SystemExit as e:
            return e.code or 0
    return capture_tool_call(wrapper)
