# SPDX-License-Identifier: Apache-2.0
"""boxmunge stash — platform stash management."""
import sys

from boxmunge.paths import BoxPaths
from boxmunge.stash import create_stash, list_stashes, restore_stash


def cmd_stash(args: list[str]) -> None:
    """CLI entry point for stash subcommands."""
    if not args:
        print("Usage: boxmunge stash {create|restore|list}")
        sys.exit(1)

    subcmd = args[0]
    paths = BoxPaths()

    if subcmd == "create":
        archive = create_stash(paths)
        print(f"Stash created: {archive.name}")
        sys.exit(0)

    elif subcmd == "restore":
        if "--latest" not in args:
            print("Usage: boxmunge stash restore --latest")
            sys.exit(1)
        try:
            restored = restore_stash(paths)
            print(f"Restored from: {restored.name}")
            sys.exit(0)
        except FileNotFoundError as e:
            print(f"ERROR: {e}")
            sys.exit(1)

    elif subcmd == "list":
        stashes = list_stashes(paths)
        if not stashes:
            print("No stashes found.")
        else:
            for s in stashes:
                print(f"  {s.name}")
        sys.exit(0)

    else:
        print(f"Unknown stash subcommand: {subcmd}")
        sys.exit(1)
