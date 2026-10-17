# SPDX-License-Identifier: Apache-2.0
"""Restricted boxmunge shell — login shell for the deploy user.

Parses SSH commands, dispatches boxmunge commands, and rejects everything else.
Handles scp uploads by routing them through the reception handler.
"""

from __future__ import annotations

import os
import pwd
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, MutableMapping

from boxmunge.as_deploy import shell_environment

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# Every command the deploy shell accepts. This is the complete allowlist.
ALLOWED_COMMANDS: set[str] = {
    # Host operations
    "help", "agent-help", "doctor", "status", "test-alert", "handshake", "version",
    # Project lifecycle
    "add-git-project", "stage", "promote", "unstage",
    "prod-deploy", "rollback", "project-delete", "diff",
    "project-add", "project-list",
    "pause", "resume", "recover",
    # Data: `data adopt` names an anonymous volume
    "data",
    # Inbox
    "inbox",
    # Secrets
    "secrets",
    # Container security & CVE policy.
    # - `security` (no args / <project>): introspection
    # - `security scan|suppress|unsuppress|resume`: mutating
    # Operator-only forms (host-scope suppressions, scan --apply-held) are
    # refused by operator_only_reason below.
    "security",
    # Project operations.
    # `check` is read-only. `check-all` is the timer-driven mutator: it
    # writes per-project health state, can call compose_down on critical
    # results, and emits Pushover notifications. Use `check-all --read-only`
    # for an introspection-only run that prints the report without side
    # effects. The deploy user has access to both forms; the systemd timer
    # at systemd/boxmunge-health.service uses the mutator form.
    "check", "check-all", "log", "logs",
    "backup", "backup-all", "backup-sync",
    "restore", "validate",
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

def operator_only_reason(command: str, args: list[str]) -> str | None:
    """Why this form of an allowed command is refused here, or None.

    Some forms of an allowed command reach beyond one project and stay
    operator-only: run them as the supervisor account, not through the
    deploy shell.
    """
    if command == "security" and args[:1] in (["suppress"], ["unsuppress"]) \
            and "--host" in args:
        return (
            "host-scope suppressions apply to every project on the box and "
            "are operator-only"
        )
    if command == "security" and args[:1] == ["scan"] and "--apply-held" in args:
        return (
            "applying quarantines held by the CVE circuit breaker is "
            "operator-only"
        )
    return None


def _shell_banner() -> str:
    """Build the interactive-shell banner including the installed version."""
    from boxmunge.version import get_build_version
    return f"""\
boxmunge deploy shell ({get_build_version()})

This is a restricted shell. Available commands:

  help                Show all commands
  agent-help          AI agent orientation
  version             Show installed boxmunge version
  status              Dashboard of all projects
  prod-deploy <project>  Deploy to production (skip staging)
  stage <project>     Stage for verification
  promote <project>   Promote staging to production
  inbox               List uploaded bundles
  secrets             Manage secrets

Upload bundles with: scp -O bundle.tar.gz deploy@<host>:

Run 'help' for the full command list.
"""


def parse_shell_command(command_string: str) -> tuple[str, list[str]]:
    """Parse an SSH command string into (command, args).

    Returns ("", []) for empty/whitespace input.
    Returns ("scp", args) for scp protocol commands.
    Silently strips a leading 'boxmunge' prefix so that
    'boxmunge help' and 'help' are equivalent.

    Raises ValueError when the quoting is unbalanced. Guessing (for example
    by splitting on whitespace) would run a command with arguments the
    caller did not write.
    """
    stripped = command_string.strip()
    if not stripped:
        return "", []

    parts = shlex.split(stripped)

    # Strip leading 'boxmunge' so agents/users can type either form
    if parts and parts[0] == "boxmunge":
        parts = parts[1:]
    if not parts:
        return "", []

    return parts[0], parts[1:]


def handle_scp_upload(args: list[str]) -> None:
    """Handle an scp upload by receiving to a temp dir, then filing to inbox.

    Delegates to the real scp binary for protocol handling, with the
    destination rewritten to a private directory for this session under the
    inbox temp area. Concurrent uploads share that area, so this session
    files and removes only what it received itself. The client's own target
    path is ignored.
    """
    from boxmunge.paths import BoxPaths
    from boxmunge.reception import receive_bundle

    paths = BoxPaths()
    # A hangup or kill mid-transfer would otherwise skip the cleanup below and
    # strand this session's partial upload. Installed before the directory
    # exists, so no window leaves one behind.
    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, _exit_on_signal)
    session_dir: Path | None = None
    try:
        paths.inbox_tmp.mkdir(parents=True, exist_ok=True)
        _sweep_abandoned_uploads(paths)
        session_dir = Path(tempfile.mkdtemp(dir=paths.inbox_tmp, prefix="scp-"))
        result = subprocess.run(["/usr/bin/scp", "-t", str(session_dir)], check=False)
        if result.returncode != 0:
            print("ERROR: scp upload failed.", file=sys.stderr)
            sys.exit(1)

        received_files = sorted(session_dir.iterdir())
        if not received_files:
            print("ERROR: No file received.", file=sys.stderr)
            sys.exit(1)

        for received in received_files:
            try:
                dest = receive_bundle(received, paths)
                print(f"Received: {dest.name}")
            except ValueError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                sys.exit(1)
    finally:
        if session_dir is not None:
            shutil.rmtree(session_dir)


# Uploads untouched for this long were abandoned by a session that could not
# clean up (SIGKILL, power loss). A live transfer writes continuously, so its
# newest mtime is always recent.
_ABANDONED_UPLOAD_SECONDS = 24 * 3600


def _newest_mtime(path: Path) -> float:
    newest = path.lstat().st_mtime
    if path.is_dir() and not path.is_symlink():
        for child in path.rglob("*"):
            newest = max(newest, child.lstat().st_mtime)
    return newest


def _sweep_abandoned_uploads(paths: BoxPaths) -> None:
    """Remove session dirs, and flat files from the old shared layout, idle for a day.

    An entry that cannot be removed is logged and left; it must not stop
    this upload.
    """
    from boxmunge.log import log_warning
    cutoff = time.time() - _ABANDONED_UPLOAD_SECONDS
    for entry in paths.inbox_tmp.iterdir():
        try:
            if _newest_mtime(entry) >= cutoff:
                continue
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
        except FileNotFoundError:
            continue  # its own session finished and cleaned up meanwhile
        except OSError as e:
            log_warning("upload", f"cannot remove abandoned upload {entry}: {e}", paths)


def _exit_on_signal(signum: int, _frame: object) -> None:
    sys.exit(128 + signum)


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
    #   boxmunge-shell -c "/opt/boxmunge/bin/boxmunge-sftp"
    # deploy gets no SFTP: sftp-server would run with deploy's full
    # filesystem access, outside this allowlist (A-04). Uploads use legacy
    # scp (`scp -O`), received above through `scp -t`.
    cmd_base = os.path.basename(command) if "/" in command else command
    if cmd_base in ("sftp-server", "boxmunge-sftp"):
        from boxmunge.sftp_receive import SFTP_REFUSAL
        print(SFTP_REFUSAL, file=sys.stderr)
        return 1

    if command not in ALLOWED_COMMANDS:
        print(
            f"ERROR: Unknown command '{command}'. "
            "Run 'help' for available commands.",
            file=sys.stderr,
        )
        return 1

    denied = operator_only_reason(command, args)
    if denied is not None:
        print(
            f"ERROR: Not available in the deploy shell: {denied}. "
            "Ask the operator to run it as the supervisor account.",
            file=sys.stderr,
        )
        return 1

    if command == "upgrade":
        return _run_upgrade(args)

    result = subprocess.run(["boxmunge-server", command] + args)
    return result.returncode


# `upgrade` forms deploy may use. --dry-run and --help run in-process and
# write nothing; everything else needs root and goes through the shim.
_UPGRADE_IN_PROCESS = (["--dry-run"], ["-h"], ["--help"])


def _run_upgrade(args: list[str]) -> int:
    """Route `upgrade` the same way MCP does: through the sudo shim.

    The shim (root, via a sudo rule scoped to `auto` and `target <version>`)
    verifies the release signature, swaps venvs and runs probation. The
    shim-internal `--apply` would do none of that if run here as deploy, so
    it is refused, as is anything else this function does not recognise.
    """
    from boxmunge.paths import BoxPaths
    from boxmunge.upgrade_shim import shim_command

    if not args:
        argv = shim_command(BoxPaths())
    elif args[0] == "--target":
        if len(args) != 2 or not args[1]:
            print(
                "ERROR: --target takes exactly one version "
                "(e.g. `upgrade --target 0.3.5`)",
                file=sys.stderr,
            )
            return 2
        argv = shim_command(BoxPaths(), target=args[1])
    elif args in _UPGRADE_IN_PROCESS:
        argv = ["boxmunge-server", "upgrade", *args]
    else:
        print(
            f"ERROR: `upgrade {' '.join(args)}` is not available from the deploy shell. "
            "Use `upgrade`, `upgrade --target <version>` or `upgrade --dry-run`.",
            file=sys.stderr,
        )
        return 2
    return subprocess.run(argv).returncode


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
    print(_shell_banner())
    while True:
        try:
            line = input("boxmunge> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        try:
            command, args = parse_shell_command(line)
        except ValueError as e:
            _report_parse_error(e)
            continue
        if not command:
            continue
        cmd_base = os.path.basename(command) if "/" in command else command
        if cmd_base in ("sftp-server", "boxmunge-sftp", "scp"):
            print("ERROR: This command is not available in interactive mode.", file=sys.stderr)
            continue
        run_command(command, args)


def _report_parse_error(error: ValueError) -> None:
    print(f"ERROR: cannot parse command ({error}). Check the quoting and retry.",
          file=sys.stderr)


def _dispatch_string(command_string: str) -> None:
    try:
        command, args = parse_shell_command(command_string)
    except ValueError as e:
        _report_parse_error(e)
        sys.exit(2)
    dispatch_command(command, args)


def restrict_environment(env: MutableMapping[str, str]) -> None:
    """Keep only as_deploy.KEPT_ENV and LC_*; set PATH and the account's own variables."""
    kept = shell_environment(env, pwd.getpwuid(os.getuid()))
    env.clear()
    env.update(kept)


def main() -> None:
    """Entry point for the boxmunge-shell login shell.

    Called by SSH as: boxmunge-shell -c "command string"
    Or with SSH_ORIGINAL_COMMAND env var when using ForceCommand.
    With no command: starts an interactive loop.
    """
    restrict_environment(os.environ)
    # SSH passes the command via -c when used as a login shell
    if len(sys.argv) >= 3 and sys.argv[1] == "-c":
        _dispatch_string(sys.argv[2])
        return

    # ForceCommand mode
    command_string = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if command_string:
        _dispatch_string(command_string)
        return

    # No command — interactive session
    interactive_loop()
