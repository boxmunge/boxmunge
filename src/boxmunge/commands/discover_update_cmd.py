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


_FLAGS = frozenset({"--json", "--auto"})


def cmd_discover_update(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, usage_error
    parsed = parse_args("_discover-update", args, flags=set(_FLAGS))
    if not parsed.has("--json"):
        usage_error("_discover-update", "--json is required")
    paths = BoxPaths()
    mode = "latest"
    if parsed.has("--auto"):
        try:
            mode = auto_update_mode(load_config(paths))
        except ConfigError as e:
            print(json.dumps({"action": "error",
                              "message": f"Cannot read auto-update policy: {e}"}))
            sys.exit(0)
    result = discover_update(paths, mode=mode)
    print(json.dumps(result))
    sys.exit(0)
