# SPDX-License-Identifier: Apache-2.0
"""Server commands for this project (secrets, rollback, validate) and a
passthrough for any other server command."""

from __future__ import annotations

import argparse
import getpass
import re
import sys

from boxmunge_cli.confirming import needs_terminal
from boxmunge_cli.remote_cmds import connect
from boxmunge_cli.ssh import run_ssh

_SECRET_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


_STDIN_SECRETS = "'secrets set' with the value on stdin"


def _read_secret_value(key: str) -> str | None:
    """The value for KEY: prompted without echo at a terminal, else one stdin line."""
    if sys.stdin.isatty():
        return getpass.getpass(f"Value for {key}: ")
    line = sys.stdin.readline()
    if not line:
        print(f"ERROR: no value for {key} on stdin.", file=sys.stderr)
        return None
    return line.rstrip("\n")


def _has_line_break(key: str, value: str) -> bool:
    if "\n" not in value and "\r" not in value:
        return False
    print(f"ERROR: the value for {key} contains a line break, which a secret cannot "
          f"hold. Nothing was sent.", file=sys.stderr)
    return True


def _secrets_set(key: str, sep: str, value: str) -> int:
    """Send the value on ssh's stdin, never in a command line (ours or the
    server's). The server takes it there from 0.11.5; an older one is
    refused by the handshake before the value is read or sent."""
    config = connect(features=(_STDIN_SECRETS,))
    if not sep:
        read = _read_secret_value(key)
        if read is None:
            return 1
        value = read
    if _has_line_break(key, value):
        return 2
    return run_ssh(config, "secrets", "set", config["project"], key, stdin_text=value + "\n")


def _cmd_secrets(args: argparse.Namespace) -> int:
    if args.action == "list":
        if args.key is not None:
            print("ERROR: secrets list takes no KEY.", file=sys.stderr)
            return 2
        config = connect()
        return run_ssh(config, "secrets", "list", config["project"])
    if args.key is None:
        print(f"ERROR: secrets {args.action} needs a KEY.", file=sys.stderr)
        return 2
    key, sep, value = args.key.partition("=")
    if not _SECRET_KEY.fullmatch(key):
        print(f"ERROR: invalid secret name {key!r}.", file=sys.stderr)
        return 2
    if args.action == "set":
        if _has_line_break(key, value):
            return 2
        return _secrets_set(key, sep, value)
    if sep:
        print(f"ERROR: secrets {args.action} takes a KEY, not KEY=VALUE.", file=sys.stderr)
        return 2
    config = connect()
    return run_ssh(config, "secrets", args.action, config["project"], key)


def _cmd_rollback(args: argparse.Namespace) -> int:
    extra = ["--yes"] if args.yes else []
    tty = needs_terminal("rollback", extra, "boxmunge rollback")
    config = connect()
    return run_ssh(config, "rollback", config["project"], *extra, tty=tty)


def _cmd_validate(args: argparse.Namespace) -> int:
    config = connect()
    return run_ssh(config, "validate", config["project"], *(["--json"] if args.json else []))


def _cmd_remote(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("ERROR: remote needs a server command, e.g. boxmunge remote inbox",
              file=sys.stderr)
        return 2
    tty = needs_terminal(command[0], command[1:], "boxmunge remote " + " ".join(command))
    config = connect()
    return run_ssh(config, command[0], *command[1:], tty=tty)


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "secrets", help="Manage this project's secrets on the server",
        description="Run 'secrets <action> <project>' on the server. Secrets live "
                    "in the project's secrets.env on the server, never in a bundle. "
                    "'set KEY' reads the value from a terminal prompt (no echo) or "
                    "from one line of stdin, and sends it to the server on ssh's "
                    "stdin: it is in no shell history and in no command line, so "
                    "process listings (ps) here and on the server do not show it. "
                    "'set KEY=VALUE' still sends it that way, but the value is then "
                    "in your shell history and in this command's own process "
                    "listing. On the server the value is stored in plain text in "
                    "secrets.env, readable by the deploy user and root, and the "
                    "containers of every service the manifest declares get it in "
                    "their environment. "
                    "'set' needs boxmunge-server 0.11.5 or newer.")
    p.add_argument("action", choices=["set", "get", "list", "unset"])
    p.add_argument("key", nargs="?", metavar="KEY[=VALUE]")
    p.set_defaults(func=_cmd_secrets)

    p = subparsers.add_parser(
        "rollback", help="Roll production back to the previous deploy",
        description="Run 'rollback <project>' on the server. At a terminal the server "
                    "shows what it will restore and asks before acting; without one "
                    "(a script, CI), --yes is required.")
    p.add_argument("--yes", action="store_true",
                   help="Do not ask for confirmation (required when standard input is not a "
                        "terminal)")
    p.set_defaults(func=_cmd_rollback)

    p = subparsers.add_parser("validate", help="Validate the deployed project on the server",
                              description="Run 'validate <project>' on the server.")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p.set_defaults(func=_cmd_validate)

    p = subparsers.add_parser(
        "remote", help="Run any server command, e.g. 'remote inbox'",
        description="Run a server command over SSH, with every argument quoted. "
                    "The server's restricted shell decides what is allowed; run "
                    "'boxmunge remote help' for its command list. Commands that ask "
                    "before acting (pause, resume, recover, restore, rollback, "
                    "inbox clean, project-delete) ask at a terminal; without one, "
                    "add --yes.")
    p.add_argument("command", nargs=argparse.REMAINDER, metavar="COMMAND [ARGS...]")
    p.set_defaults(func=_cmd_remote)
