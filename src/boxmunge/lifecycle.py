# SPDX-License-Identifier: Apache-2.0
"""Project lifecycle-state aggregation.

Unifies the multiple "this project is intentionally not running" state
files (paused, CVE-quarantined) behind a single is_blocked() predicate.
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


class BlockReason(Enum):
    PAUSED = "paused"
    QUARANTINED = "quarantined"


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

    Order matters: quarantine takes precedence over pause if both
    state files exist (a quarantine landing on a paused project is
    rare but reachable; the security action is the more-specific one).
    """
    if is_quarantined(project_name, paths):
        state = read_quarantine_state(project_name, paths) or {}
        cve = state.get("cve_id", "<unknown>")
        return Block(
            reason=BlockReason.QUARANTINED,
            detail=state,
            refuse_message=(
                f"Project '{project_name}' is CVE-quarantined ({cve}). "
                f"Deploy a fixed release (prod-deploy or promote; its "
                f"images are scanned first), or run `boxmunge security "
                f"resume {project_name}` once the images it would start "
                f"are clean."
            ),
            skip_message=(
                f"Skipped quarantined project '{project_name}' — deploy a "
                f"fixed release or use `boxmunge security resume` to lift"
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


def refuse_if_blocked(project_name: str, paths: BoxPaths, *,
                      ships_fix: bool = False) -> bool:
    """Print the refusal and return True if the project is blocked.

    Operate cores call this under the project lock, immediately before
    they mutate: a pause or quarantine that completed while the caller
    waited for the lock must win (see boxmunge.fileutil, "Lock order").

    ``ships_fix``: a deploy, promote or stage, which may carry the fix for
    a quarantine. A quarantine alone lets it through, because it scans the
    images its release would start before anything starts and refuses if
    a quarantine-level finding remains (commands/quarantine_gate). A pause
    is the operator's own decision and still refuses.
    """
    block = is_blocked(project_name, paths)
    if block is None:
        return False
    if ships_fix and block.reason is BlockReason.QUARANTINED:
        if not is_paused(project_name, paths):
            cve = block.detail.get("cve_id", "<unknown>")
            print(f"  {project_name} is CVE-quarantined ({cve}): "
                  f"the images this release would start are scanned before anything "
                  f"starts, and the release is refused if a quarantine-level finding "
                  f"remains.")
            return False
        print(f"ERROR: Project '{project_name}' is paused and CVE-quarantined. A deploy "
              f"does not end a pause: run `boxmunge security resume {project_name}` once "
              f"its images are clean (it stays paused), then `boxmunge resume "
              f"{project_name}`.", file=sys.stderr)
        return True
    print(f"ERROR: {block.refuse_message}", file=sys.stderr)
    return True
