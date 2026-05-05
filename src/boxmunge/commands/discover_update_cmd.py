# SPDX-License-Identifier: Apache-2.0
"""Internal command: _discover-update --json [--security-only]

Called by scripts/boxmunge-upgrade. Not exposed to users (leading
underscore in the command name); not in shell.ALLOWED_COMMANDS.

Always prints JSON to stdout. Exits 0 on successful discovery
(JSON contract carries success/error info via "action" field).
Exits 2 if --json flag is missing.
"""
import json
import sys

from boxmunge.paths import BoxPaths
from boxmunge.upgrade_discovery import discover_update


def cmd_discover_update(args: list[str]) -> None:
    if "--json" not in args:
        print("Usage: boxmunge _discover-update --json [--security-only]",
              file=sys.stderr)
        sys.exit(2)
    security_only = "--security-only" in args
    paths = BoxPaths()
    result = discover_update(paths, security_only=security_only)
    print(json.dumps(result))
    sys.exit(0)
