# SPDX-License-Identifier: Apache-2.0
"""Server commands for this project (secrets, rollback, validate) and a
passthrough for any other server command."""

from __future__ import annotations

import argparse
import getpass
import re
import sys

from boxmunge_cli.remote_cmds import connect
from boxmunge_cli.ssh import run_ssh

_SECRET_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _read_secret_value(key: str) -> str | None:
    """The value for KEY: prompted without echo at a terminal, else one stdin line."""
    if sys.stdin.isatty():
        return getpass.getpass(f"Value for {key}: ")
    line = sys.stdin.readline()
    if not line:
        print(f"ERROR: no value for {key} on stdin.", file=sys.stderr)
        return None
    return line.rstrip("\n")


def _cmd_secrets(args: argparse.Namespace) -> int:
    server_args: list[str] = [args.action]
    if args.action in ("set", "get", "unset"):
        if args.key is None:
            print(f"ERROR: secrets {args.action} needs a KEY.", file=sys.stderr)
            return 2
        key, sep, value = args.key.partition("=")
        if not _SECRET_KEY.fullmatch(key):
            print(f"ERROR: invalid secret name {key!r}.", file=sys.stderr)
            return 2
        if args.action == "set":
            if not sep:
                read = _read_secret_value(key)
                if read is None:
                    return 1
                value = read
            server_args.append(f"{key}={value}")
        elif sep:
            print(f"ERROR: secrets {args.action} takes a KEY, not KEY=VALUE.", file=sys.stderr)
            return 2
        else:
            server_args.append(key)
    elif args.key is not None:
        print("ERROR: secrets list takes no KEY.", file=sys.stderr)
        return 2
    config = connect()
    action, *rest = server_args
    return run_ssh(config, "secrets", action, config["project"], *rest)


def _cmd_rollback(args: argparse.Namespace) -> int:
    config = connect()
    return run_ssh(config, "rollback", config["project"], *(["--yes"] if args.yes else []))


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
    config = connect()
    return run_ssh(config, command[0], *command[1:])


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "secrets", help="Manage this project's secrets on the server",
        description="Run 'secrets <action> <project>' on the server. Secrets live "
                    "in the project's secrets.env on the server, never in a bundle. "
                    "'set KEY' reads the value from a terminal prompt (no echo) or "
                    "from one line of stdin, keeping it out of shell history.")
    p.add_argument("action", choices=["set", "get", "list", "unset"])
    p.add_argument("key", nargs="?", metavar="KEY[=VALUE]")
    p.set_defaults(func=_cmd_secrets)

    p = subparsers.add_parser("rollback", help="Roll production back to the previous deploy",
                              description="Run 'rollback <project>' on the server.")
    p.add_argument("--yes", action="store_true", help="Do not ask for confirmation")
    p.set_defaults(func=_cmd_rollback)

    p = subparsers.add_parser("validate", help="Validate the deployed project on the server",
                              description="Run 'validate <project>' on the server.")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p.set_defaults(func=_cmd_validate)

    p = subparsers.add_parser(
        "remote", help="Run any server command, e.g. 'remote inbox'",
        description="Run a server command over SSH, with every argument quoted. "
                    "The server's restricted shell decides what is allowed; run "
                    "'boxmunge remote help' for its command list.")
    p.add_argument("command", nargs=argparse.REMAINDER, metavar="COMMAND [ARGS...]")
    p.set_defaults(func=_cmd_remote)
