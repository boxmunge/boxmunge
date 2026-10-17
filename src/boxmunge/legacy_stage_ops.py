# SPDX-License-Identifier: Apache-2.0
"""The steps of `legacy-stage` (spec 'boxmunge-server legacy-stage'), each
idempotent, and this release's own copies of the two 0.10.1 operations
they need (0.10.1's release.py restore_prestage / prestage_to_previous).

The choice is recorded first (legacy_stage's record) and a rerun must name
it again. The stage stays detected until step 6, so a crash anywhere
before it is finished by running the same command again; after it, the
record's choice finishes step 7. The stash is never touched: the command
refuses while a platform rollback could still restore it.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from boxmunge.backup import BackupKind, parse_snapshot
from boxmunge.caddy import prepare_caddy_config
from boxmunge.caddy_journal import remove_site
from boxmunge.commands.deploy_steps import record_deploy_state, snapshot_wanted
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.commands.upgrade_steps import (
    _compose_refusal, _write_maintenance_site, require_manifest,
)
from boxmunge.compose import prepare_compose_override
from boxmunge.compose_guard import check_start, compose_up_checked
from boxmunge.data_dirs import log_kept, set_aside_announcer
from boxmunge.docker import DockerError, caddy_config_lock, caddy_reload, compose_down
from boxmunge.fileutil import (
    atomic_write_text, chown_tree_deploy, discard_dir, durable_rename_dir, fsync_dir,
)
from boxmunge.git_layout import alert_unlinked, relink_advice
from boxmunge.legacy_stage import (
    LEGACY_STAGING_FILES, Evidence, LegacyStage, drop_record, get_record,
    legacy_staging_compose, legacy_staging_state, update_record,
)
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_operation
from boxmunge.manifest import load_manifest, load_manifest_as_written
from boxmunge.notify import notify
from boxmunge.release import install_release, live_code_entries, mark_live, previous_meta_text
from boxmunge.staging_cleanup import remove_retired_staging_data
from boxmunge.state import read_state
from boxmunge.upgrade_exclusions import migrate_one
from boxmunge.upgrade_state import read_probation

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

COMPONENT = "legacy-stage"
PROD_FILES = ["compose.yml", "compose.boxmunge.yml"]


class LegacyStageError(Exception):
    """The legacy stage cannot be resolved as asked."""


def platform_rollback_possible(paths: BoxPaths) -> str | None:
    """Why a platform rollback could still restore the pre-upgrade stash
    (which holds the staged files) over a resolved production, or None."""
    probation = read_probation(paths)
    if probation:
        return (f"the upgrade to {probation.get('version')} is on probation until "
                f"{probation.get('expires_at')}; a platform rollback would restore the "
                f"pre-upgrade stash over a resolved production")
    for name in ("upgrade-inflight", "rollback-inflight"):
        for marker in sorted(paths.root.glob(f"env-*/{name}")):
            return (f"an interrupted platform upgrade or rollback is pending ({marker}); "
                    f"the upgrade shim finishes it")
    return None


def allowed_choices(stage: LegacyStage) -> list[str]:
    return ["discard"] if stage.kind == "leftover" else ["discard", "keep-staged"]


def predeploy_snapshots(paths: BoxPaths, project: str,
                        after: datetime | None = None) -> list[str]:
    """Pre-deploy snapshot names, newest first, made after `after` (by the
    time in their name, which a copy or touch cannot change)."""
    found = []
    backups = paths.project_backups(project)
    for path in backups.glob(f"{project}-*.tar.gz.age") if backups.is_dir() else ():
        parsed = parse_snapshot(path, project)
        if parsed is None or parsed[1] is not BackupKind.PREDEPLOY:
            continue
        made = datetime.strptime(parsed[0], "%Y-%m-%dT%H%M%S").replace(tzinfo=timezone.utc)
        if after is None or made > after:
            found.append((made, path.name))
    return [name for _, name in sorted(found, reverse=True)]


# -- 0.10.1's prestage operations, on this release's durable helpers --------

def _prestage_ref(paths: BoxPaths, project: str) -> str | None:
    meta = paths.project_releases(project) / "prestage" / "meta.json"
    ref = json.loads(meta.read_text()).get("ref")
    if ref is not None and not isinstance(ref, str):
        raise LegacyStageError(f"{meta}: ref {ref!r} is not a string")
    return ref


def restore_prestage_0101(paths: BoxPaths, project: str) -> None:
    """Put the kept production release back (0.10.1's restore_prestage,
    without its discard: step 6 does that)."""
    pdir, releases = paths.project_dir(project), paths.project_releases(project)
    ref = _prestage_ref(paths, project)
    kept = install_release(releases / "prestage" / "release", pdir,
                           set_aside_announcer(paths, project, COMPONENT))
    log_kept(paths, project, kept, COMPONENT)
    if ref is None:
        if os.path.lexists(releases / "live.json"):
            (releases / "live.json").unlink()
            fsync_dir(releases)
    else:
        mark_live(paths, project, ref)
    for entry in live_code_entries(pdir):
        chown_tree_deploy(entry)


def prestage_to_previous_0101(paths: BoxPaths, project: str, snapshot: str | None,
                              replaced_by: str) -> None:
    """The kept production release becomes the rollback target (0.10.1's
    prestage_to_previous, without its discard). Safe to rerun after the move."""
    ref = _prestage_ref(paths, project)
    if ref is None:
        return  # the stage was a first deploy: nothing to roll back to
    releases = paths.project_releases(project)
    tree, previous = releases / "prestage" / "release", releases / "previous"
    if os.path.lexists(tree):
        if os.path.lexists(releases / "previous.json"):
            (releases / "previous.json").unlink()
            fsync_dir(releases)
        discard_dir(previous)
        durable_rename_dir(tree, previous)
    elif not previous.is_dir():
        raise LegacyStageError(f"{tree} is gone and {previous} does not hold it")
    atomic_write_text(releases / "previous.json", previous_meta_text(
        ref, snapshot, datetime.now(timezone.utc).isoformat(), replaced_by), mode=0o644)
    chown_tree_deploy(previous)


# -- the steps (spec "Steps"; step 1, the record, is the command's) ---------

def _stop_legacy_staging(paths: BoxPaths, project: str) -> None:
    """Step 2. Recorded once done: after step 4 the base compose.yml is
    production's, which may no longer hold the staging overlay's services."""
    files = legacy_staging_compose(paths.project_dir(project))
    if files is None or (get_record(paths, project) or {}).get("staging_down"):
        return
    compose_down(paths.project_dir(project), compose_files=files,
                 project_name=f"{project}-staging", remove_orphans=True)
    update_record(paths, project, staging_down=True)


def _remove_staging_site(paths: BoxPaths, project: str) -> None:
    """Step 3, as unstage does it."""
    with caddy_config_lock(paths.state):
        remove_site(paths.caddy, paths.project_staging_caddy_site(project))
    try:
        caddy_reload(paths.caddy, paths.state)
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")


def _snapshot_production(paths: BoxPaths, project: str) -> str | None:
    """A pre-deploy snapshot of the untouched production, with the manifest
    and compose file of the release its containers run (backup_source)."""
    from boxmunge.backup_source import backup_source
    from boxmunge.commands.backup_cmd import backup_locked, list_snapshots
    source = backup_source(paths, project)
    if source.manifest is None:
        raise LegacyStageError(f"production cannot be backed up: {source.skip}")
    if not snapshot_wanted(source.manifest):
        return None
    print("  Taking pre-deploy snapshot...")
    if backup_locked(project, paths, kind=BackupKind.PREDEPLOY, manifest=source.manifest,
                     compose_file=source.compose_file) != 0:
        raise LegacyStageError("the pre-deploy snapshot failed (see above); without it a "
                               "rollback could not restore production's data")
    snaps = list_snapshots(paths, project)
    return snaps[0].name if snaps else None


def _pairing_snapshot(paths: BoxPaths, project: str, ev: Evidence) -> str | None:
    """The snapshot the kept production release pairs with, decided once."""
    rec = get_record(paths, project) or {}
    if "snapshot" not in rec:
        if ev.classification == "untouched":
            name = _snapshot_production(paths, project)
        else:
            after = predeploy_snapshots(paths, project, after=ev.t)
            name = after[0] if after else None
        rec = update_record(paths, project, snapshot=name or "")
    return rec["snapshot"] or None


def _production_code(paths: BoxPaths, project: str, stage: LegacyStage,
                     ev: Evidence | None, choice: str) -> None:
    """Step 4."""
    if stage.kind == "leftover":
        return  # production runs the release a 0.10.1 promote installed
    assert ev is not None
    if choice == "discard":
        if stage.kind == "bundle":
            restore_prestage_0101(paths, project)
        else:
            from boxmunge.git_slot import checkout_detached, resolve_recorded_ref
            repo = paths.project_dir(project) / "repo"
            checkout_detached(repo, resolve_recorded_ref(repo, ev.current_ref or ""))
        return
    snapshot = _pairing_snapshot(paths, project, ev)
    staged = ev.staged_ref if stage.kind == "bundle" else ev.head
    if not staged:
        raise LegacyStageError("the staged release's ref is not known")
    if stage.kind == "bundle":
        prestage_to_previous_0101(paths, project, snapshot, staged)
    if read_state(paths.project_deploy_state(project)).get("current_ref") != staged:
        record_deploy_state(paths, project, staged, snapshot)


def _clean_up(paths: BoxPaths, project: str) -> None:
    """Step 5."""
    remove_retired_staging_data(paths, project)
    pdir = paths.project_dir(project)
    for path in (*(pdir / name for name in LEGACY_STAGING_FILES),
                 paths.project_bind_record(project, staging=True)):
        if os.path.lexists(path):
            path.unlink()
            fsync_dir(path.parent)


def _drop_stage_record(paths: BoxPaths, project: str) -> None:
    """Step 6, last: detection is true until this is done."""
    state = legacy_staging_state(paths, project)
    if os.path.lexists(state):
        state.unlink()
        fsync_dir(state.parent)
    discard_dir(paths.project_releases(project) / "prestage")


def finish_apply(paths: BoxPaths, project: str) -> None:
    """Step 7: what the upgrade apply skipped (the manifest migration and the
    configs), then production recreated on this release's overlay as a
    deploy does. A paused, quarantined or monitor-stopped project is left
    stopped, with its bind sources recorded for the command that starts it."""
    pdir = paths.project_dir(project)
    manifest_path = require_manifest(pdir)
    unlinked = alert_unlinked(paths, pdir, load_manifest_as_written(manifest_path))
    if unlinked:
        print(f"  WARN: {relink_advice(pdir, unlinked)}")
    migrate_one(paths, pdir)
    manifest = load_manifest(manifest_path)
    refusal = _compose_refusal(paths, project, manifest)
    if refusal is not None:
        raise LegacyStageError(f"compose.yml is refused: {refusal}. Fix it and run this "
                               f"again, or deploy a fixed release")
    prepare_compose_override(paths, manifest, component=COMPONENT)
    block = is_blocked(project, paths)
    held = (f"it is {block.reason.value}" if block else
            "the health monitor stopped it; `recover` starts it"
            if is_monitor_stopped(project, paths) else None)
    if block:
        _write_maintenance_site(paths, project, manifest)
    else:
        prepare_caddy_config(paths, manifest)
    if held:
        check_start(paths, project, component=COMPONENT, compose_files=PROD_FILES,
                    record=True, deploying=True)
        print(f"  {project} was not started: {held}.")
        return
    compose_up_checked(paths, project, component=COMPONENT, compose_files=PROD_FILES,
                       record=True, deploying=True)
    try:
        caddy_reload(paths.caddy, paths.state)
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")


def resolve(paths: BoxPaths, project: str, stage: LegacyStage, ev: Evidence | None,
            choice: str) -> None:
    """Steps 2-7. Caller has recorded the choice (step 1) and holds the lock."""
    _stop_legacy_staging(paths, project)
    _remove_staging_site(paths, project)
    _production_code(paths, project, stage, ev, choice)
    _clean_up(paths, project)
    _drop_stage_record(paths, project)
    finish_apply(paths, project)


def report_resolved(paths: BoxPaths, project: str, choice: str) -> None:
    """Step 8."""
    drop_record(paths, project)
    log_operation(COMPONENT, f"Resolved the release staged by boxmunge 0.10.1: --{choice}",
                  paths, project=project, detail={"choice": choice})
    notify(paths, f"{project}: 0.10.1 stage resolved",
           f"The release staged by boxmunge 0.10.1 was resolved with --{choice}.",
           component=COMPONENT, project=project, priority=0)
