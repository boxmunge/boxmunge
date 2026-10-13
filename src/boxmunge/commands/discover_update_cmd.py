# SPDX-License-Identifier: Apache-2.0
"""Internal command: _discover-update --json [--auto]

Called by scripts/boxmunge-upgrade. Not exposed to users (leading
underscore in the command name); not in shell.ALLOWED_COMMANDS.

Without --auto, discovers the newest release of any class (manual
upgrade). With --auto, discovers what auto-update would apply under this
box's boxmunge.yml (security, plus break-fix unless disabled).

Always prints JSON to stdout. Exits 0 on successful discovery
(JSON contract carries success/error info via "action" field).
Exits 2 if --json flag is missing.
"""
import json
import sys

from boxmunge.config import ConfigError, load_config
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_discovery import auto_update_mode, discover_update


USAGE = "Usage: boxmunge _discover-update --json [--auto]"
_FLAGS = frozenset({"--json", "--auto"})


def cmd_discover_update(args: list[str]) -> None:
    unknown = [a for a in args if a not in _FLAGS]
    if unknown:
        print(f"ERROR: unknown argument(s): {' '.join(unknown)}\n{USAGE}", file=sys.stderr)
        sys.exit(2)
    if "--json" not in args:
        print(USAGE, file=sys.stderr)
        sys.exit(2)
    paths = BoxPaths()
    mode = "latest"
    if "--auto" in args:
        try:
            mode = auto_update_mode(load_config(paths))
        except ConfigError as e:
            print(json.dumps({"action": "error",
                              "message": f"Cannot read auto-update policy: {e}"}))
            sys.exit(0)
    result = discover_update(paths, mode=mode)
    print(json.dumps(result))
    sys.exit(0)
