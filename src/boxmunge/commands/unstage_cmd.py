"""boxmunge unstage <project> — take staging down and drop the slot.

Production's tree is not touched: the slot holds release code only, and
staging's data copies stay (they are reused by the next stage), except
copies of entries production no longer mounts. Each step is idempotent and
the slot is removed last, so a failed (or killed) unstage is finished by
running it again: the slot's debris alone is still staging to tear down.
"""
from __future__ import annotations

import os
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING

from boxmunge.caddy_journal import remove_site
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.docker import DockerError, caddy_config_lock, caddy_reload, compose_down
from boxmunge.fileutil import LockError, project_lock
from boxmunge.log import log_error, log_operation
from boxmunge.legacy_stage import refuse_if_legacy_stage
from boxmunge.lifecycle import migration_refusal
from boxmunge.production_stopped import start_again, unreadable_slot_discarded
from boxmunge.release_txn import load_txn, options_text
from boxmunge.staged_release import (
    SlotError, StagedRelease, drop_slot, has_slot, load_slot, manual_teardown,
    promoted_debris, slot_debris, staging_target, sweep_debris, update_meta,
)
from boxmunge.staging_cleanup import remove_retired_staging_data

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def staging_exists(project: str, paths: BoxPaths) -> bool:
    return has_slot(paths, project) or paths.project_staging_caddy_site(project).exists()


def _read_meta(project: str, paths: BoxPaths, component: str) -> StagedRelease | None:
    try:
        return load_slot(paths, project)
    except SlotError as e:
        unreadable_slot_discarded(paths, project, component, e, "tearing staging down "
                                  "with the slot's compose files")
        return None


def _stop_staging(project: str, paths: BoxPaths, meta: StagedRelease | None,
                  component: str) -> bool:
    """compose down <p>-staging with the slot's files. On failure nothing
    else is removed, so a retry can still reach the containers."""
    target = staging_target(paths, project)
    try:
        compose_down(target.cwd, **target.kwargs())
    except DockerError as e:
        print(f"ERROR: Removing the staging containers failed: {e}. Nothing else was "
              f"removed, so 'unstage {project}' can retry. By hand: "
              f"{manual_teardown(paths, project)}", file=sys.stderr)
        log_error(component, f"Staging container teardown failed: {e}", paths,
                  project=project)
        if meta is not None:
            update_meta(paths, project, meta, cleanup_incomplete=str(e))
        return False
    return True


def teardown_staging_locked(project: str, paths: BoxPaths, *, component: str = "unstage",
                            promoted: Callable[[], None] | None = None) -> bool:
    """Take staging down and drop the slot. Caller holds the lock. Returns
    False if a step failed (each failure is reported, never raised: stage
    and promote call this in their own failure paths). ``promoted`` is
    promote's announcement, made once staging is down and before the slot
    is dropped as promoted (staged_release.drop_slot)."""
    try:
        if not _take_down(project, paths, component):
            return False
        if promoted is not None:
            promoted()
        drop_slot(paths, project, promoted=promoted is not None)
        return True
    except (OSError, SlotError) as e:
        print(f"ERROR: Tearing staging down failed: {e}", file=sys.stderr)
        log_error(component, f"Tearing staging down failed: {e}", paths, project=project)
        return False


def _take_down(project: str, paths: BoxPaths, component: str) -> bool:
    """Everything but dropping the slot, each step idempotent."""
    sweep_debris(paths, project)  # refuses a planted link before any compose call
    meta = _read_meta(project, paths, component)
    if meta is not None and meta.production_stopped:
        try:
            start_again(paths, project, component=component, alert=True)
        except DockerError:
            return False  # said loudly; the marker is kept for the next try
        meta = _read_meta(project, paths, component)
    if has_slot(paths, project) and not _stop_staging(project, paths, meta, component):
        return False
    with caddy_config_lock(paths.state):
        remove_site(paths.caddy, paths.project_staging_caddy_site(project))
    try:
        caddy_reload(paths.caddy, paths.state)
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")
    for record in (paths.project_bind_record(project, staging=True),
                   paths.project_users_record(project, staging=True)):
        if os.path.lexists(record):
            record.unlink()
    # Which copies are retired depends on what production's compose.yml
    # mounts; that file is always production's now.
    try:
        remove_retired_staging_data(paths, project, meta.made if meta is not None else ())
    except (OSError, ValueError, DockerError) as e:
        print(f"ERROR: Removing retired staging data failed: {e}", file=sys.stderr)
        log_error(component, f"Removing retired staging data failed: {e}", paths, project=project)
        return False
    return True


def promote_needs_slot(project: str, paths: BoxPaths) -> str | None:
    """Why an open promote needs this slot to resume, or None. A slot or
    install record that cannot be read cannot be told apart from that one,
    so it is kept too. Caller holds the lock."""
    try:
        txn = load_txn(paths, project)
    except ReleaseStateError as e:
        return str(e)
    if txn is None or txn.source != "staged":
        return None
    try:
        meta = load_slot(paths, project)
    except SlotError as e:
        return (f"'{project}' has a promote open (phase {txn.phase}) and the staged "
                f"slot's record cannot be read ({e}), so the install may need this slot. "
                f"{options_text(project, txn)}.")
    if meta is None or txn.staged_id != meta.id:
        return None
    return (f"'{project}' is being promoted from this staged release (phase "
            f"{txn.phase}); its install needs the slot. {options_text(project, txn)}.")


def _refuse_if_promoting(project: str, paths: BoxPaths) -> bool:
    reason = promote_needs_slot(project, paths)
    if reason is not None:
        print(f"ERROR: {reason}", file=sys.stderr)
    return reason is not None


def unstage_locked(project: str, paths: BoxPaths, dry_run: bool = False) -> int:
    """The unstage core. Caller holds the project lock; never takes it."""
    refusal = migration_refusal(f"Unstaging '{project}'", paths)
    if refusal:
        print(f"ERROR: {refusal}", file=sys.stderr)
        return 1
    if refuse_if_legacy_stage(paths, project):
        return 1
    if not staging_exists(project, paths) and not slot_debris(paths, project):
        print(f"ERROR: No staging found for '{project}'.", file=sys.stderr)
        return 1
    if not dry_run and not staging_exists(project, paths) and promoted_debris(paths, project):
        return _finish_promoted_drop(project, paths)
    if _refuse_if_promoting(project, paths):
        return 1
    if dry_run:
        print(f"[DRY RUN] Would tear down staging for '{project}'")
        return 0
    print(f"Unstaging {project}...")
    if not teardown_staging_locked(project, paths):
        print(f"ERROR: Staging for '{project}' was only partly torn down; fix the errors "
              f"above and run 'unstage {project}' again.", file=sys.stderr)
        return 1
    log_operation("unstage", "Unstaged", paths, project=project)
    print(f"{project}: staging torn down.")
    from boxmunge.webhooks import webhook_safe
    webhook_safe("unstage", project, paths)
    return 0


def _finish_promoted_drop(project: str, paths: BoxPaths) -> int:
    """A promote was killed while dropping the slot it had announced: the
    removal is all that is left, and it was a promotion, not an unstage."""
    try:
        sweep_debris(paths, project)
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(f"{project}: removed what an interrupted promote left of the staged slot; "
          f"nothing is staged.")
    return 0


def run_unstage(project_name: str, paths: BoxPaths, dry_run: bool = False) -> int:
    """unstage: take the project lock and tear down staging. Returns 0 on
    success, 1 on failure."""
    try:
        with project_lock(project_name, paths):
            return unstage_locked(project_name, paths, dry_run)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_unstage(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    from boxmunge.paths import BoxPaths
    parsed = parse_args(
        "unstage", args, flags={"--dry-run"}, min_positional=1, max_positional=1,
    )
    project = require_project_name("unstage", parsed.positional[0])
    paths = BoxPaths()
    sys.exit(run_unstage(project, paths, dry_run=parsed.has("--dry-run")))
