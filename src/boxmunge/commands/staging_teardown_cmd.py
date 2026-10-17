# SPDX-License-Identifier: Apache-2.0
"""boxmunge-server staging-teardown-all --reason platform-rollback

Run by the upgrade shim with the release being rolled back from, before it
swaps back (D14): an older release does not know the slot. Every project's
staged release is torn down with the unstage core and the operator is told
to re-stage it. A failure, or a project whose lock is held, is alerted with
that project's manual commands and never blocks the rollback, so this
always exits 0.
"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from boxmunge.commands.unstage_cmd import teardown_staging_locked
from boxmunge.fileutil import LockError, project_lock
from boxmunge.log import log_error, log_operation
from boxmunge.notify import notify
from boxmunge.staged_release import has_slot, manual_teardown

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

REASONS = ("platform-rollback",)
DISCARDED = "staged release discarded by the platform rollback; re-stage it"


def _tear_down(paths: BoxPaths, name: str, reason: str) -> bool:
    """The unstage core under the project's lock, never waited for."""
    try:
        with project_lock(name, paths):
            return teardown_staging_locked(name, paths, component=reason)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error(reason, f"Staged release not torn down: {e}", paths, project=name)
        return False


def run_staging_teardown_all(paths: BoxPaths, reason: str) -> int:
    if not paths.projects.exists():
        return 0
    for project_dir in sorted(paths.projects.iterdir()):
        name = project_dir.name
        if not project_dir.is_dir() or not has_slot(paths, name):
            continue
        if _tear_down(paths, name, reason):
            log_operation(reason, "Staged release torn down", paths, project=name)
            notify(paths, f"{name}: staged release discarded", DISCARDED,
                   component=reason, project=name, priority=1)
        else:
            notify(paths, f"{name}: staged release not torn down",
                   f"The platform rollback could not tear down {name}'s staged release; the "
                   f"older release ignores it. To remove it: {manual_teardown(paths, name)}",
                   component=reason, project=name, priority=1)
    return 0


def cmd_staging_teardown_all(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, usage_error
    from boxmunge.paths import BoxPaths
    parsed = parse_args("staging-teardown-all", args, options={"--reason"})
    reason = parsed.get("--reason")
    if reason not in REASONS:
        usage_error("staging-teardown-all", "--reason platform-rollback is required")
    sys.exit(run_staging_teardown_all(BoxPaths(), reason))
