# SPDX-License-Identifier: Apache-2.0
"""boxmunge CLI entry point — command dispatch."""

import sys
from typing import Callable

from boxmunge.commands.add_git_project_cmd import cmd_add_git_project
from boxmunge.commands.inbox_cmd import cmd_inbox
from boxmunge.commands.console import cmd_console
from boxmunge.commands.backup_cmd import cmd_backup, cmd_backup_all, cmd_backup_sync
from boxmunge.commands.caddy_status import cmd_caddy_status
from boxmunge.commands.check import cmd_check, cmd_check_all
from boxmunge.commands.deploy import cmd_deploy
from boxmunge.commands.doctor import cmd_doctor
from boxmunge.commands.help import cmd_help, cmd_agent_help
from boxmunge.commands.list_projects import cmd_list_projects
from boxmunge.commands.log_cmd import cmd_log
from boxmunge.commands.logs import cmd_logs
from boxmunge.commands.promote_cmd import cmd_promote
from boxmunge.commands.remove_project import cmd_remove_project
from boxmunge.commands.restore import cmd_restore
from boxmunge.commands.rollback import cmd_rollback
from boxmunge.commands.stage_cmd import cmd_stage
from boxmunge.commands.status import cmd_status
from boxmunge.commands.test_alert import cmd_test_alert
from boxmunge.commands.test_restore_cmd import cmd_test_restore
from boxmunge.commands.diff_cmd import cmd_diff
from boxmunge.commands.secrets_cmd import cmd_secrets
from boxmunge.commands.unstage_cmd import cmd_unstage
from boxmunge.commands.validate import cmd_validate
from boxmunge.commands.bundle_cmd import cmd_bundle
from boxmunge.commands.health_cmd import cmd_health
from boxmunge.commands.self_test_cmd import cmd_self_test
from boxmunge.commands.upgrade_cmd import cmd_upgrade
from boxmunge.commands.auto_update_cmd import cmd_auto_update
from boxmunge.commands.mcp_serve_cmd import cmd_mcp_serve
from boxmunge.commands.project_cmd import cmd_project_add, cmd_project_remove, cmd_project_list
from boxmunge.commands.handshake_cmd import cmd_handshake

# Command registry: name -> handler function
COMMANDS: dict[str, Callable[[list[str]], None]] = {
    "help": cmd_help,
    "agent-help": cmd_agent_help,
    "init-host": cmd_help,  # placeholder — init-host is the shell bootstrap
    "doctor": cmd_doctor,
    "status": cmd_status,
    "test-alert": cmd_test_alert,
    "prod-deploy": cmd_deploy,
    "inbox": cmd_inbox,
    "rollback": cmd_rollback,
    "remove-project": cmd_remove_project,
    "check": cmd_check,
    "check-all": cmd_check_all,
    "log": cmd_log,
    "logs": cmd_logs,
    "backup": cmd_backup,
    "backup-all": cmd_backup_all,
    "backup-sync": cmd_backup_sync,
    "restore": cmd_restore,
    "list-projects": cmd_list_projects,
    "validate": cmd_validate,
    "caddy-status": cmd_caddy_status,
    "test-restore": cmd_test_restore,
    "console": cmd_console,
    "add-git-project": cmd_add_git_project,
    "stage": cmd_stage,
    "promote": cmd_promote,
    "unstage": cmd_unstage,
    "secrets": cmd_secrets,
    "diff": cmd_diff,
    "bundle": cmd_bundle,
    "health": cmd_health,
    "self-test": cmd_self_test,
    "upgrade": cmd_upgrade,
    "auto-update": cmd_auto_update,
    "mcp-serve": cmd_mcp_serve,
    "project-add": cmd_project_add,
    "project-remove": cmd_project_remove,
    "project-list": cmd_project_list,
    "handshake": cmd_handshake,
}


def main() -> None:
    """Main entry point for the boxmunge CLI."""
    args = sys.argv[1:]

    if not args:
        cmd_help([])
        return

    if args[0] in ("--version", "-V"):
        from boxmunge.version import get_build_version
        print(f"boxmunge {get_build_version()}")
        return

    command = args[0]
    command_args = args[1:]

    handler = COMMANDS.get(command)
    if handler is None:
        print(f"boxmunge: unknown command '{command}'", file=sys.stderr)
        print("Run 'boxmunge help' for usage.", file=sys.stderr)
        sys.exit(2)

    handler(command_args)
