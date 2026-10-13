# SPDX-License-Identifier: Apache-2.0
"""boxmunge local CLI: argument parsing and dispatch only.

Each command module registers its own subparser and handler. Handlers return
an exit code: 0 success, 1 failure, 2 usage error (argparse also exits 2).
"""

from __future__ import annotations

import argparse
import sys

from boxmunge_cli import __version__
from boxmunge_cli import bundle_cmd, init_cmd, remote_cmds
from boxmunge_cli.server_setup import args as server_setup_args

DESCRIPTION = "boxmunge: deploy to your VPS in one command"

EPILOG = """\
Run 'boxmunge <command> --help' for a command's options.
Commands that talk to the server read connection details from the nearest
.boxmunge file (created by 'boxmunge init').
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boxmunge", description=DESCRIPTION, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version",
                        version=f"boxmunge {__version__}")
    subparsers = parser.add_subparsers(title="commands", metavar="<command>")
    init_cmd.register(subparsers)
    bundle_cmd.register(subparsers)
    remote_cmds.register(subparsers)
    server_setup_args.register(subparsers)
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)
    sys.exit(args.func(args))
