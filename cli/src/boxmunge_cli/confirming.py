# SPDX-License-Identifier: Apache-2.0
"""Server commands that print their plan and ask 'Proceed? [y/N]' before
they act (the server's commands/confirm.py).

ssh gives a remote command no terminal unless asked to (-t), and the server
refuses to ask without one, so without --yes such a command could never
succeed. At a terminal here, ssh -t lets the server show its plan and ask.
With no terminal on stdin here nobody can answer either, so the command is
refused before anything is sent, naming --yes.
"""

from __future__ import annotations

import sys

from boxmunge_cli.exitcodes import USAGE, CliExit

# Commands that ask whenever --yes is absent. `resume --no-start` hands the
# pause to a deploy without asking; `inbox` asks only for `inbox clean`.
_ASKING = frozenset({"rollback", "pause", "resume", "recover", "restore", "project-delete"})


def have_terminal() -> bool:
    """Whether a person can answer here: stdin is a terminal. stdout may be
    a pipe (`boxmunge rollback | tee log`): ssh -t still gives the server a
    pty when stdin is a terminal, and the plan and prompt reach the pipe."""
    return sys.stdin is not None and sys.stdin.isatty()  # None: stdin was closed


def asks(command: str, args: list[str] | tuple[str, ...]) -> bool:
    """Whether the server command would ask before acting."""
    if any(a in ("--yes", "-h", "--help") for a in args):
        return False
    if command == "inbox":
        return bool(args) and args[0] == "clean"
    if command == "resume" and "--no-start" in args:
        return False
    return command in _ASKING


def needs_terminal(command: str, args: list[str] | tuple[str, ...], shown: str) -> bool:
    """True when the command must run with ssh -t so the server can ask.
    Raises CliExit (usage) when it would ask and nobody here can answer;
    `shown` is how the operator typed it, for the message."""
    if not asks(command, args):
        return False
    if have_terminal():
        return True
    raise CliExit(USAGE, f"'{shown}' asks 'Proceed? [y/N]' on the server, but there is no "
                         f"terminal here to answer it. Nothing was sent. To proceed, run "
                         f"it again with --yes added.")
