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
from boxmunge.upgrade_check_result import (
    CheckResult, check_to_json, exit_code, no_verdict_in_time, parse_check, render_check,
)
from boxmunge.upgrade_shim import check_command
from boxmunge.upgrade_target import (
    TargetError, installed_release, is_newer, not_newer, resolve_target,
)

COMMAND = "upgrade-check"
# Over the shim's own worst case: three prerequisites at 60 s, the venv at
# 900 s, the readiness check and the dry run at 300 s each (1680 s), and a
# bundle download at curl's 600 s limit.
SHIM_TIMEOUT_SECS = 2400


def _check(paths: BoxPaths, target: str, installed: str) -> CheckResult:
    """The shim's verdict on `target`. A shim with no verdict in
    SHIM_TIMEOUT_SECS is left running, not killed: it runs as root, which
    deploy cannot signal, and it stops at its own limits and cleans up."""
    proc = subprocess.Popen(check_command(paths, target), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = proc.communicate(timeout=SHIM_TIMEOUT_SECS)
    except subprocess.TimeoutExpired:
        return no_verdict_in_time(target, installed, SHIM_TIMEOUT_SECS)
    return parse_check(stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace"),
                       proc.returncode, target=target, installed=installed)


def run_upgrade_check(paths: BoxPaths, version: str | None, *, as_json: bool) -> int:
    try:
        target = resolve_target(paths, version)
        installed = installed_release(paths)
        if not is_newer(target, installed):
            raise not_newer(COMMAND, target, installed, explicit=version is not None)
    except TargetError as e:
        print(f"ERROR: {COMMAND}: {e.message}", file=sys.stderr)
        return e.exit_code
    if not as_json:
        print(f"Running the readiness check of {target} against this box; it can take "
              f"several minutes...", file=sys.stderr, flush=True)
    result = _check(paths, target, installed)
    print(json.dumps(check_to_json(result)) if as_json else render_check(result))
    return exit_code(result)


def cmd_upgrade_check(args: list[str]) -> None:
    parsed = parse_args(COMMAND, args, flags={"--json"}, options={"--version"})
    sys.exit(run_upgrade_check(BoxPaths(), parsed.get("--version"),
                               as_json=parsed.has("--json")))
