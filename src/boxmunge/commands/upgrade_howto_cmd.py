# SPDX-License-Identifier: Apache-2.0
"""boxmunge upgrade-howto [--version X.Y.Z] [--json]: what to change before
and after a platform upgrade, on the box and in each project.

The target is --version, or the newest release (boxmunge.upgrade_target).
Its upgrade-notes.json comes from the root shim's `guide` verb, which
prints it only once the release's cosign-signed SHA256SUMS verifies it;
the guide is composed here (boxmunge.upgrade_guide). Nothing is sent
anywhere about this box's projects.

Exit 0: a guide was printed (an up-to-date box, and one below the upgrade
floor, get a short one). Exit 1: the notes could not be fetched, verified
or used. Exit 2: a usage error, or no --version where one must be named.
"""
from __future__ import annotations

import json
import subprocess
import sys

from boxmunge.commands.argv import parse_args
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_guide import (
    compose_guide, guide_to_json, render_guide, up_to_date_json, up_to_date_text,
)
from boxmunge.upgrade_notes import NotesError
from boxmunge.upgrade_shim import guide_command, stderr_tail, sudo_refusal
from boxmunge.upgrade_target import (
    TargetError, installed_release, is_newer, not_newer, resolve_target,
)

COMMAND = "upgrade-howto"


def _fail(message: str, exit_code: int) -> int:
    print(f"ERROR: {COMMAND}: {message}", file=sys.stderr)
    return exit_code


def _fetch_notes(paths: BoxPaths, target: str) -> bytes | str:
    """The target's verified upgrade-notes.json, or why there is none."""
    done = subprocess.run(guide_command(paths, target), stdin=subprocess.DEVNULL,
                          capture_output=True, check=False)
    if done.returncode == 0:
        return done.stdout
    stderr = done.stderr.decode("utf-8", "replace")
    return (f"the signed upgrade notes of {target} could not be fetched or verified (the "
            f"upgrade shim exited {done.returncode}): {stderr_tail(stderr)}"
            + (f". {hint}" if (hint := sudo_refusal(stderr)) else ""))


def run_upgrade_howto(paths: BoxPaths, version: str | None, *, as_json: bool) -> int:
    try:
        installed = installed_release(paths)
        target = resolve_target(paths, version)
        if target == installed:
            newest = version is None
            print(json.dumps(up_to_date_json(installed, newest=newest)) if as_json
                  else up_to_date_text(installed, newest=newest))
            return 0
        if not is_newer(target, installed):
            raise not_newer(COMMAND, target, installed, explicit=True)
    except TargetError as e:
        return _fail(e.message, e.exit_code)
    notes = _fetch_notes(paths, target)
    if isinstance(notes, str):
        return _fail(notes, 1)
    try:
        guide = compose_guide(notes, target, installed)
    except NotesError as e:
        return _fail(f"the signed upgrade notes of {target} cannot be used: {e}. Nothing "
                     f"was composed from them; upgrade-check --version {target} still checks "
                     f"this box against {target}", 1)
    print(json.dumps(guide_to_json(guide)) if as_json else render_guide(guide))
    return 0


def cmd_upgrade_howto(args: list[str]) -> None:
    parsed = parse_args(COMMAND, args, flags={"--json"}, options={"--version"})
    sys.exit(run_upgrade_howto(BoxPaths(), parsed.get("--version"),
                               as_json=parsed.has("--json")))
