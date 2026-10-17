"""boxmunge stage <project> — stage a release in its own tree beside production.

The staged release lives in <project>/.releases/staged/ (staged_release)
and staging runs from there; production's project dir, overlay, release
bookkeeping and data are never written (only read, and production is
briefly stopped for a copy_data stage). A failure after the swap tears the
whole stage down (D16).

stage_locked runs the spec's steps as named functions, in order:
_eligible, _clear_leftovers, _intake_bundle (which ends in _build_slot),
_retire_previous, _swap, bring_up_staging, _mark_ready, _announce.
"""
from __future__ import annotations

import hashlib
import sys
from typing import TYPE_CHECKING, Any

from boxmunge.commands.unstage_cmd import teardown_staging_locked
from boxmunge.docker_run import DockerError
from boxmunge.fileutil import LockError, discard_dir, durable_rename_dir, project_lock
from boxmunge.identity import register_project_identity
from boxmunge.intake import (
    IntakeError, check_installable, extract_candidate, incoming_workspace,
    report_refusal, validate_release_tree,
)
from boxmunge.lifecycle import refuse_if_blocked
from boxmunge.legacy_stage import refuse_if_legacy_stage
from boxmunge.log import log_error, log_operation
from boxmunge.production_stopped import start_again
from boxmunge.project_registry import is_registered
from boxmunge.release_txn import refuse_if_install_open
from boxmunge.source import SourceError, bundle_ref, consume_bundle, resolve_bundle_source
from boxmunge.stage_slot import build_slot, retire_previous_staging
from boxmunge.staged_release import (
    SlotError, StagedRelease, building_dir, load_slot, new_meta, release_dir, swap_in,
    sweep_debris, update_meta,
)
from boxmunge.staging_bringup import STORAGE_ERRORS, bring_up_staging
from boxmunge.staging_prepare import precheck_candidate

if TYPE_CHECKING:
    from pathlib import Path

    from boxmunge.paths import BoxPaths


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _eligible(project: str, paths: BoxPaths) -> bool:
    """Step 1, under the lock: not blocked, registered, no open install, and
    a bundle project (git staging is rebuilt on the slot later)."""
    if refuse_if_blocked(project, paths) or refuse_if_legacy_stage(paths, project):
        return False
    if not is_registered(project, paths):
        print(f"ERROR: Project '{project}' is not registered on this server. "
              f"Run: project-add {project}", file=sys.stderr)
        return False
    # An open install owns the project dir until it closes; a stage now
    # would retire a slot a staged install may need, or stage over a
    # release that is half installed.
    if refuse_if_install_open(paths, project, component="stage"):
        return False
    if (paths.project_dir(project) / "repo").exists():
        print(f"ERROR: Staging a git-sourced project is not available in this build of "
              f"boxmunge; deploy '{project}' with prod-deploy.", file=sys.stderr)
        return False
    return True


def _clear_leftovers(project: str, paths: BoxPaths) -> bool:
    """Crash debris goes, and production runs again if a crashed copy left
    it stopped, before anything else is decided. A previous slot whose
    record cannot be read is replaced by this stage (_retire_previous says
    so); stage again is the remedy promote names for it."""
    try:
        sweep_debris(paths, project)
        if _readable_slot(paths, project):
            start_again(paths, project, component="stage", alert=True)
    except (OSError, SlotError, DockerError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False
    return True


def _readable_slot(paths: BoxPaths, project: str) -> bool:
    try:
        load_slot(paths, project)
    except SlotError:
        return False
    return True


def _build_slot(project: str, paths: BoxPaths, tree: Path, manifest: dict[str, Any],
                meta: StagedRelease) -> bool:
    """Step 3: move the validated tree into staged.building and complete the
    slot there. On failure nothing remains of it."""
    building = building_dir(paths, project)
    try:
        building.mkdir()
        durable_rename_dir(tree, release_dir(building))
        build_slot(paths, project, manifest, meta)
    except STORAGE_ERRORS as e:
        print(f"ERROR: Building the staged release failed: {e}", file=sys.stderr)
        log_error("stage", f"Building the staged release failed: {e}", paths,
                  project=project)
        _discard_building(project, paths, building)
        return False
    return True


def _discard_building(project: str, paths: BoxPaths, building: Path) -> None:
    """The failed build's half-made slot goes; if that fails too, both
    errors are said and the next stage (or deploy) sweeps it."""
    try:
        discard_dir(building)
    except OSError as e:
        print(f"ERROR: Removing the half-built {building} failed too: {e}. Production and "
              f"any staged release were not changed; the next 'stage {project}' removes "
              f"it.", file=sys.stderr)
        log_error("stage", f"Removing the half-built staged release failed: {e}", paths,
                  project=project)
        return
    print("Nothing was changed.", file=sys.stderr)


def _intake_bundle(project: str, paths: BoxPaths, ref: str | None,
                   dry_run: bool) -> tuple[dict[str, Any], Path] | int:
    """Step 2: validate the inbox bundle in .releases/incoming/ and prove its
    staging apart from production, then build the slot from it. Returns
    (manifest, bundle path) or an exit code."""
    try:
        bundle_path = resolve_bundle_source(project, paths, ref=ref)
    except SourceError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    project_dir = paths.project_dir(project)
    try:
        with incoming_workspace(paths, project) as workspace:
            tree = extract_candidate(bundle_path, workspace)
            manifest = validate_release_tree(tree, project, paths, "stage")
            check_installable(tree, project_dir)
            try:
                precheck_candidate(paths, project, manifest, tree, workspace)
            except STORAGE_ERRORS as e:
                print(f"ERROR: {e}\nNothing was changed.", file=sys.stderr)
                log_error("stage", f"Stage refused: {e}", paths, project=project)
                return 1
            if dry_run:
                print(f"[DRY RUN] Would stage '{project}'")
                return 0
            meta = new_meta("bundle", bundle_ref(bundle_path), _sha256(bundle_path))
            if not _build_slot(project, paths, tree, manifest, meta):
                return 1
    except IntakeError as e:
        return report_refusal(e)
    return manifest, bundle_path


def _retire_previous(project: str, paths: BoxPaths) -> bool:
    """Step 4. On failure the new slot is dropped and the old one stays
    `starting`: nothing is promotable and unstage cleans up."""
    try:
        retire_previous_staging(paths, project)
    except (DockerError, OSError, SlotError) as e:
        discard_dir(building_dir(paths, project))
        print(f"ERROR: Stopping the previous staging failed: {e}. The new release was not "
              f"staged; 'unstage {project}' removes the previous one.", file=sys.stderr)
        log_error("stage", f"Stopping the previous staging failed: {e}", paths,
                  project=project)
        return False
    return True


def stage_locked(project: str, paths: BoxPaths, ref: str | None = None,
                 dry_run: bool = False) -> int:
    """The stage core. Caller holds the project lock; never takes it. A dry
    run changes nothing, so it leaves crash debris and a stopped production
    for the real stage (or the health tick) to clear."""
    if not _eligible(project, paths):
        return 1
    if not dry_run and not _clear_leftovers(project, paths):
        return 1
    candidate = _intake_bundle(project, paths, ref, dry_run)
    if isinstance(candidate, int):
        return candidate
    manifest, bundle_path = candidate
    if not _retire_previous(project, paths):
        return 1
    # From the swap on, any failure tears the whole stage down (D16).
    ready: StagedRelease | None = None
    try:
        rc = bring_up_staging(paths, project, manifest) if _swap(project, paths) else 1
        if rc == 0:
            ready = _mark_ready(project, paths)
            rc = 0 if ready else 1
    finally:
        if not ready:
            print("  Stage failed; cleaning up...")
            if teardown_staging_locked(project, paths, component="stage"):
                print(f"  Staging for '{project}' cleaned up.")
            else:
                print(f"ERROR: Cleanup after the failed stage was incomplete; "
                      f"run 'unstage {project}'.", file=sys.stderr)
    if ready:
        _announce(project, paths, ready, manifest, bundle_path)
    return rc


def _swap(project: str, paths: BoxPaths) -> bool:
    """Step 5: staged.building becomes the slot."""
    try:
        swap_in(paths, project)
    except OSError as e:
        print(f"ERROR: Putting the staged release in place failed: {e}", file=sys.stderr)
        log_error("stage", f"Swapping in the staged release failed: {e}", paths,
                  project=project)
        return False
    return True


def _mark_ready(project: str, paths: BoxPaths) -> StagedRelease | None:
    """Step 7: the stage completed; only now can promote deploy it. Returns
    the record as written, or None."""
    try:
        meta = load_slot(paths, project)
        if meta is None:
            raise SlotError(f"the staged slot of '{project}' is gone")
        return update_meta(paths, project, meta, state="ready")
    except (OSError, SlotError) as e:
        print(f"ERROR: Recording the stage as ready failed: {e}", file=sys.stderr)
        log_error("stage", f"Recording the stage as ready failed: {e}", paths,
                  project=project)
        return None


def _announce(project: str, paths: BoxPaths, meta: StagedRelease, manifest: dict[str, Any],
              bundle_path: Path) -> None:
    register_project_identity(project, manifest.get("id", ""), paths)
    consume_bundle(bundle_path, project, paths)
    print("  Staged at:")
    for host in manifest.get("hosts", []):
        print(f"    https://staging.{host}")
    print(f"  Run 'promote {project}' to go live, or 'unstage {project}' to tear down.")
    log_operation("stage", f"Staged {meta.ref}", paths, project=project,
                  detail={"ref": meta.ref, "id": meta.id})
    from boxmunge.webhooks import webhook_safe
    webhook_safe("stage", project, paths, details={"ref": meta.ref, "id": meta.id})


def run_stage(project_name: str, paths: BoxPaths, ref: str | None = None,
              dry_run: bool = False) -> int:
    """stage: take the project lock and stage. Returns 0 on success, 1 on failure."""
    try:
        with project_lock(project_name, paths):
            return stage_locked(project_name, paths, ref, dry_run)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_stage(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    from boxmunge.paths import BoxPaths
    parsed = parse_args(
        "stage", args, flags={"--dry-run"}, options={"--ref"},
        min_positional=1, max_positional=1,
    )
    project = require_project_name("stage", parsed.positional[0])
    sys.exit(run_stage(project, BoxPaths(), ref=parsed.get("--ref"),
                       dry_run=parsed.has("--dry-run")))
