# SPDX-License-Identifier: Apache-2.0
"""Project lifecycle-state aggregation.

Unifies the multiple "this project is intentionally not running" state
files (paused, CVE-quarantined, a userns migration) behind a single
is_blocked() predicate.
Callers consult this once before mutating compose state — operator-
initiated flows refuse loudly, cron-driven flows skip with a structured
log entry.

Adding a new lifecycle state (e.g. scheduled-maintenance) means
extending BlockReason here; callers don't change.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any

from boxmunge.cve.quarantine import is_quarantined, read_quarantine_state
from boxmunge.pause import is_paused, read_paused_state
from boxmunge.paths import BoxPaths
from boxmunge.userns.marker import SHIM, migration_in_progress


class BlockReason(Enum):
    PAUSED = "paused"
    QUARANTINED = "quarantined"
    MIGRATING = "migrating"  # the Docker daemon's userns migration (userns.marker)


@dataclass(frozen=True)
class Block:
    """Why a project is currently blocked from mutating compose ops."""

    reason: BlockReason
    detail: dict[str, Any]  # state-file content (paused_at, cve_id, etc.)
    refuse_message: str     # operator-facing error for REFUSE flows
    skip_message: str       # log_operation message for SKIP flows


def is_blocked(project_name: str, paths: BoxPaths) -> Block | None:
    """Return a Block describing why the project is intentionally not
    running, or None if it's free to mutate.

    A userns migration in progress (or stopped part-way) comes first: the
    daemon and the project's data are between two states, and nothing but
    the migration may start or change it. Then quarantine takes precedence
    over pause if both state files exist (a quarantine landing on a paused
    project is rare but reachable; the security action is the more-specific
    one).
    """
    finish = migration_in_progress(paths)
    if finish is not None:
        return Block(
            reason=BlockReason.MIGRATING,
            detail={"finish": finish},
            refuse_message=(
                f"Project '{project_name}' cannot be changed while the Docker daemon's "
                f"user-namespace migration is in progress or stopped part-way. The "
                f"supervisor finishes it: {SHIM} {finish}"),
            skip_message=(f"Skipped '{project_name}': a userns migration is in progress "
                          f"({SHIM} {finish} finishes it)"),
        )
    return lifecycle_block(project_name, paths)


def lifecycle_block(project_name: str, paths: BoxPaths) -> Block | None:
    """is_blocked without the migration: what the migration's own bring-up
    honours (a paused or quarantined project stays down)."""
    if is_quarantined(project_name, paths):
        state = read_quarantine_state(project_name, paths) or {}
        cve = state.get("cve_id", "<unknown>")
        return Block(
            reason=BlockReason.QUARANTINED,
            detail=state,
            refuse_message=(
                f"Project '{project_name}' is CVE-quarantined ({cve}). "
                f"Run `boxmunge security resume {project_name}` to "
                f"restore.\n"
                f"       (Resume re-scans first; if a quarantine-level "
                f"finding remains, you must suppress or wait for "
                f"upstream fix.)"
            ),
            skip_message=(
                f"Skipped quarantined project '{project_name}' — use "
                f"`boxmunge security resume` to lift"
            ),
        )
    if is_paused(project_name, paths):
        state = read_paused_state(project_name, paths) or {}
        return Block(
            reason=BlockReason.PAUSED,
            detail=state,
            refuse_message=(
                f"Project '{project_name}' is paused. "
                f"Run `boxmunge resume {project_name}` to bring back "
                f"online."
            ),
            skip_message=f"Skipped paused project '{project_name}'",
        )
    return None


def migration_refusal(what: str, paths: BoxPaths) -> str | None:
    """Why `what` may not run now, for a command that changes the box but
    no one project (self-test), or None."""
    finish = migration_in_progress(paths)
    if finish is None:
        return None
    return (f"{what} cannot run while the Docker daemon's user-namespace migration is in "
            f"progress or stopped part-way. The supervisor finishes it: {SHIM} {finish}")


def refuse_if_blocked(project_name: str, paths: BoxPaths) -> bool:
    """Print the refusal and return True if the project is blocked.

    Operate cores call this under the project lock, immediately before
    they mutate: a pause or quarantine that completed while the caller
    waited for the lock must win (see boxmunge.fileutil, "Lock order").
    """
    block = is_blocked(project_name, paths)
    if block:
        print(f"ERROR: {block.refuse_message}", file=sys.stderr)
    return block is not None
