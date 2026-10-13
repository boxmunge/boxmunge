# SPDX-License-Identifier: Apache-2.0
"""boxmunge version — print the installed version."""

import sys

from boxmunge.version import get_build_version


def cmd_version(args: list[str]) -> None:
    """Print the installed boxmunge version."""
    from boxmunge.commands.argv import parse_args
    parse_args("version", args)
    print(f"boxmunge {get_build_version()}")
    sys.exit(0)
