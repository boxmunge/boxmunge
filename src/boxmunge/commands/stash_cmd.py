# SPDX-License-Identifier: Apache-2.0
"""boxmunge stash — platform stash management."""
import sys

from boxmunge.paths import BoxPaths
from boxmunge.stash import StashError, create_stash, list_stashes, restore_stash


def cmd_stash(args: list[str]) -> None:
    """CLI entry point for stash subcommands."""
    from boxmunge.commands.argv import usage_error
    if args not in (["create"], ["list"], ["restore", "--latest"]):
        usage_error("stash", f"invalid arguments: {' '.join(args) or '(none)'}")

    subcmd = args[0]
    paths = BoxPaths()

    if subcmd == "create":
        try:
            created = create_stash(paths)
        except StashError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        # The upgrade shim reads both lines: it records the size and sha256
        # printed here instead of hashing the deploy-writable name.
        print(f"Stash created: {created.path.name}")
        print(f"Stash digest: {created.size} {created.sha256}")
        sys.exit(0)

    elif subcmd == "restore":
        try:
            restored = restore_stash(paths)
            print(f"Restored from: {restored.name}")
            sys.exit(0)
        except (FileNotFoundError, StashError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    else:  # list
        stashes = list_stashes(paths)
        if not stashes:
            print("No stashes found.")
        else:
            for s in stashes:
                print(f"  {s.name}")
        sys.exit(0)
