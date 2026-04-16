# SPDX-License-Identifier: Apache-2.0
"""Restricted boxmunge shell — login shell for the deploy user.

Parses SSH commands, dispatches boxmunge commands, and rejects everything else.
Handles scp uploads by routing them through the reception handler.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

# Every command the deploy shell accepts. This is the complete whitelist.
ALLOWED_COMMANDS: set[str] = {
    # Host operations
    "help", "agent-help", "doctor", "status", "test-alert",
    # Project lifecycle
    "add-git-project", "stage", "promote", "unstage",
    "deploy", "rollback", "remove-project", "diff",
    # Inbox
    "inbox",
    # Secrets
    "secrets",
    # Project operations
    "check", "check-all", "log", "logs",
    "backup", "backup-all", "backup-sync",
    "restore", "list-projects", "validate",
    "caddy-status", "test-restore",
    # TUI
    "console",
    # Health audit
    "health",
    # Self-test
    "self-test",
    # Upgrade
    "upgrade",
    # Auto-update
    "auto-update",
    # MCP server
    "mcp-serve",
}

SHELL_BANNER = """\
boxmunge deploy shell

This is a restricted shell. Available commands:

  help                Show all commands
  agent-help          AI agent orientation
  status              Dashboard of all projects
  deploy <project>    Deploy to production
  stage <project>     Stage for verification
  promote <project>   Promote staging to production
  inbox               List uploaded bundles
  secrets             Manage secrets

Upload bundles with: scp bundle.tar.gz deploy@<host>:

Run 'help' for the full command list.
"""


def parse_shell_command(command_string: str) -> tuple[str, list[str]]:
    """Parse an SSH command string into (command, args).

    Returns ("", []) for empty/whitespace input.
    Returns ("scp", args) for scp protocol commands.
    """
    stripped = command_string.strip()
    if not stripped:
        return "", []

    try:
        parts = shlex.split(stripped)
    except ValueError:
        parts = stripped.split()

    return parts[0], parts[1:]


def handle_scp_upload(args: list[str]) -> None:
    """Handle an scp upload by receiving to a temp dir, then filing to inbox.

    Delegates to the real scp binary for protocol handling, with the
    destination rewritten to the inbox temp directory. After scp completes,
    the received file is processed by the reception handler.
    """
    from boxmunge.paths import BoxPaths
    from boxmunge.reception import receive_bundle

    paths = BoxPaths()
    paths.inbox_tmp.mkdir(parents=True, exist_ok=True)

    scp_args = ["/usr/bin/scp", "-t", str(paths.inbox_tmp)]
    result = subprocess.run(scp_args, check=False)

    if result.returncode != 0:
        # Clean temp before exiting
        for leftover in paths.inbox_tmp.iterdir():
            leftover.unlink(missing_ok=True)
        print("ERROR: scp upload failed.", file=sys.stderr)
        sys.exit(1)

    received_files = list(paths.inbox_tmp.iterdir())
    if not received_files:
        print("ERROR: No file received.", file=sys.stderr)
        sys.exit(1)

    try:
        for received in received_files:
            try:
                dest = receive_bundle(received, paths)
                print(f"Received: {dest.name}")
            except ValueError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                received.unlink(missing_ok=True)
                sys.exit(1)
    finally:
        # Clean any remaining temp files
        for leftover in paths.inbox_tmp.iterdir():
            leftover.unlink(missing_ok=True)


def _handle_sftp(command: str, args: list[str]) -> int:
    """Handle SFTP subsystem — run sftp-server, then post-process uploads.

    sshd invokes the login shell with: -c "/usr/lib/openssh/sftp-server"
    We run the real sftp-server, then process any new files in $HOME into
    the inbox. This is a fallback — normally sftp_receive.py handles this
    via the sshd Subsystem directive.
    """
    from boxmunge.paths import BoxPaths
    from boxmunge.reception import receive_bundle

    paths = BoxPaths()
    deploy_home = Path.home()

    # Snapshot files before sftp
    before = set(f.name for f in deploy_home.iterdir() if f.is_file()) \
        if deploy_home.exists() else set()

    # Run the real sftp-server — it inherits stdin/stdout for the protocol
    result = subprocess.run([command] + args, check=False)

    # Find and process new files
    after = set(f.name for f in deploy_home.iterdir() if f.is_file()) \
        if deploy_home.exists() else set()

    for fname in sorted(after - before):
        fpath = deploy_home / fname
        if not fpath.exists():
            continue
        try:
            dest = receive_bundle(fpath, paths)
            print(f"Received: {dest.name}", file=sys.stderr)
        except ValueError:
            fpath.unlink(missing_ok=True)

    return result.returncode


def run_command(command: str, args: list[str]) -> int:
    """Run a single boxmunge command. Returns exit code.

    For scp -t: handle upload via reception handler.
    For allowed commands: run boxmunge as subprocess.
    For everything else: print error and return 1.
    """
    if command == "exit" or command == "quit":
        sys.exit(0)

    if command == "scp":
        if args and args[0] == "-t":
            handle_scp_upload(args)
            return 0
        print("ERROR: Downloads via scp are not supported.", file=sys.stderr)
        return 1

    # SFTP subsystem — sshd routes this through the login shell as:
    #   boxmunge-shell -c "/usr/lib/openssh/sftp-server"
    # Run sftp-server, then post-process any new uploads via home-dir snapshot.
    if command in ("sftp-server", "/usr/lib/openssh/sftp-server"):
        return _handle_sftp(command, args)

    if command not in ALLOWED_COMMANDS:
        print(
            f"ERROR: Unknown command '{command}'. "
            "Run 'help' for available commands.",
            file=sys.stderr,
        )
        return 1

    result = subprocess.run(["boxmunge", command] + args)
    return result.returncode


def dispatch_command(command: str, args: list[str]) -> None:
    """Dispatch a single command and exit. Used for non-interactive mode."""
    if not command:
        # Empty command from -c "" — exit silently. This happens during
        # SSH session setup (e.g., before SFTP subsystem starts). Printing
        # anything to stdout would corrupt the SFTP protocol channel.
        sys.exit(0)

    sys.exit(run_command(command, args))


def interactive_loop() -> None:
    """Run an interactive command loop for human SSH sessions."""
    print(SHELL_BANNER)
    while True:
        try:
            line = input("boxmunge> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        command, args = parse_shell_command(line)
        if not command:
            continue
        if command in ("sftp-server", "/usr/lib/openssh/sftp-server", "scp"):
            print("ERROR: This command is not available in interactive mode.", file=sys.stderr)
            continue
        run_command(command, args)


def main() -> None:
    """Entry point for the boxmunge-shell login shell.

    Called by SSH as: boxmunge-shell -c "command string"
    Or with SSH_ORIGINAL_COMMAND env var when using ForceCommand.
    With no command: starts an interactive loop.
    """
    # SSH passes the command via -c when used as a login shell
    if len(sys.argv) >= 3 and sys.argv[1] == "-c":
        command_string = sys.argv[2]
        command, args = parse_shell_command(command_string)
        dispatch_command(command, args)
        return

    # ForceCommand mode
    command_string = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if command_string:
        command, args = parse_shell_command(command_string)
        dispatch_command(command, args)
        return

    # No command — interactive session
    interactive_loop()
