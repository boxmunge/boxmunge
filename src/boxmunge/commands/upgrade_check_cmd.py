# SPDX-License-Identifier: Apache-2.0
"""boxmunge upgrade-check [--version X.Y.Z] [--json]: is this box ready for
an upgrade to the target release?

The target is --version, or the newest release (boxmunge.upgrade_target).
The root shim's `check` verb fetches and verifies that release, runs its
prerequisite scripts, builds it a scratch venv, and runs its own readiness
command and upgrade pre-flight against the live box, confined, as the deploy
user. It prints one JSON verdict, read here failing closed
(boxmunge.upgrade_check_result). It can take several minutes, and a check
starts at least 10 minutes after the last one ended.

Exit 0 PASS, 1 BLOCKED or CAN'T VERIFY, 2 a usage error or no target to
check (an up-to-date box; no --version where one must be named).
"""
from __future__ import annotations

import json
import subprocess
import sys

from boxmunge.commands.argv import parse_args
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_check_result import check_to_json, exit_code, parse_check, render_check
from boxmunge.upgrade_shim import check_command
from boxmunge.upgrade_target import (
    TargetError, installed_release, is_newer, not_newer, resolve_target,
)

COMMAND = "upgrade-check"


def run_upgrade_check(paths: BoxPaths, version: str | None, *, as_json: bool) -> int:
    try:
        installed = installed_release(paths)
        target = resolve_target(paths, version)
        if not is_newer(target, installed):
            raise not_newer(COMMAND, target, installed, explicit=version is not None)
    except TargetError as e:
        print(f"ERROR: {COMMAND}: {e.message}", file=sys.stderr)
        return e.exit_code
    if not as_json:
        print(f"Running the readiness check of {target} against this box; it can take "
              f"several minutes...", file=sys.stderr, flush=True)
    done = subprocess.run(check_command(paths, target), stdin=subprocess.DEVNULL,
                          capture_output=True, check=False)
    result = parse_check(done.stdout.decode("utf-8", "replace"),
                         done.stderr.decode("utf-8", "replace"), done.returncode,
                         target=target, installed=installed)
    print(json.dumps(check_to_json(result)) if as_json else render_check(result))
    return exit_code(result)


def cmd_upgrade_check(args: list[str]) -> None:
    parsed = parse_args(COMMAND, args, flags={"--json"}, options={"--version"})
    sys.exit(run_upgrade_check(BoxPaths(), parsed.get("--version"),
                               as_json=parsed.has("--json")))
