# SPDX-License-Identifier: Apache-2.0
"""The y/N confirmation a command asks before it changes anything.

Over ssh without a terminal (`ssh deploy@box pause myapp`) nobody can
answer: input() raises EOFError when stdin is closed and waits forever
when it is open. Such a run is refused, before anything changes, with a
message naming --yes. MCP tools pass yes themselves and never get here.
"""
from __future__ import annotations

import sys


def confirm(command: str) -> bool:
    """Ask "Proceed? [y/N]" for `command`. False, after saying why, when the
    operator declines or when stdin is not a terminal; the caller then
    returns without acting."""
    if sys.stdin is None or not sys.stdin.isatty():
        print(f"ERROR: '{command}' asks 'Proceed? [y/N]', but stdin is not a terminal, "
              f"so nobody can answer (ssh runs a command without one unless given -t). "
              f"Nothing was changed. To proceed, run the same command again with "
              f"--yes added.", file=sys.stderr)
        return False
    try:
        answer = input("\nProceed? [y/N] ")
    except EOFError:
        print()
        answer = ""
    if answer.lower() != "y":
        print("Aborted.")
        return False
    return True
