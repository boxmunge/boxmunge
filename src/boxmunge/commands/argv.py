# SPDX-License-Identifier: Apache-2.0
"""Strict argument parsing shared by command handlers.

Every token must be accounted for. A flag or option the command does not
declare, or a surplus positional, is a usage error: ``ERROR:`` plus the
command's usage on stderr, exit 2. Nothing is silently ignored, so a typo or
an unsupported flag (notably ``--dry-run``) can never fall through to the
command's default, possibly destructive, action.

``-h`` / ``--help`` are handled once, in ``cli.main``, before any handler
runs.
"""

import sys
from dataclasses import dataclass
from typing import NoReturn

from boxmunge.commands.usage import usage_for

HELP_FLAGS = frozenset({"-h", "--help"})


@dataclass(frozen=True)
class Args:
    positional: list[str]
    flags: frozenset[str]
    options: dict[str, str]

    def has(self, flag: str) -> bool:
        return flag in self.flags

    def get(self, option: str) -> str | None:
        return self.options.get(option)


def print_usage_error(command: str, message: str) -> None:
    """Print a usage error and the command's usage to stderr."""
    print(f"ERROR: {message}", file=sys.stderr)
    print(usage_for(command), file=sys.stderr)


def usage_error(command: str, message: str) -> NoReturn:
    """Print a usage error and exit 2."""
    print_usage_error(command, message)
    sys.exit(2)


def _is_flag_like(token: str) -> bool:
    return token.startswith("-") and token != "-"


def parse_args(
    command: str,
    args: list[str],
    *,
    flags: frozenset[str] | set[str] = frozenset(),
    options: frozenset[str] | set[str] = frozenset(),
    min_positional: int = 0,
    max_positional: int = 0,
) -> Args:
    """Parse ``args`` strictly, or exit 2 with usage.

    ``flags`` are boolean switches; ``options`` take the next token as
    their value (``--ref main``). Positionals are any other token that does
    not start with ``-``.
    """
    seen: set[str] = set()
    values: dict[str, str] = {}
    positional: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token in options:
            if i + 1 >= len(args):
                usage_error(command, f"{token} requires a value")
            if token in values:
                usage_error(command, f"{token} given more than once")
            values[token] = args[i + 1]
            i += 2
            continue
        if token in flags:
            seen.add(token)
        elif token == "--dry-run":
            usage_error(
                command,
                f"'{command}' does not support --dry-run; nothing was done",
            )
        elif _is_flag_like(token):
            usage_error(command, f"unknown argument: {token}")
        else:
            positional.append(token)
        i += 1

    if len(positional) < min_positional:
        usage_error(command, "missing required argument")
    if len(positional) > max_positional:
        extra = " ".join(positional[max_positional:])
        usage_error(command, f"unexpected argument(s): {extra}")
    return Args(positional=positional, flags=frozenset(seen), options=values)


def require_project_name(command: str, name: str) -> str:
    """Validate a project name argument, or exit 2."""
    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(name)
    except ValueError as e:
        usage_error(command, str(e))
    return name
