# SPDX-License-Identifier: Apache-2.0
"""Rollback (D6): a migration in reverse, from a fresh inventory of the remapped daemon.

Nothing is blocked during the soak, so the forward journal is not replayed:
everything the remapped daemon holds now (projects, volumes, images created
during the soak included) goes back. The order matters: with both daemons
stopped, old-root volumes get their data back and every bind source is
unshifted before the old daemon starts, because the old daemon drops a
volume whose _data is missing and restarts restart-policy containers at
once. Volumes created during the soak are made in the old daemon after it
starts; nothing references them yet. A migration stopped before the daemon
switch is simply aborted. Every step is journalled before the next, so a
kill at any point is resumed by running userns-rollback again.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from boxmunge.docker_run import run as _run
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import load_registered_projects
from boxmunge.userns import offset as uo
from boxmunge.userns.bringup import bring_up, quiesce
from boxmunge.userns.commit import COMMIT_STARTED
from boxmunge.userns.daemon_ctl import DaemonControl, TimerControl, daemon_answers
from boxmunge.userns.engine import Save, project_locks, shift_journalled
from boxmunge.userns.images import IMAGES_DIR, load_all, remove_tars, save_all
from boxmunge.userns.inventory import Inventory, outermost, take_inventory
from boxmunge.userns.marker import clear_marker, migration_in_progress, set_marker
from boxmunge.userns.steps import report_back
from boxmunge.userns.journal import FORWARD, ROLLBACK, Journal, load_journal, save_journal
from boxmunge.userns.preflight import PreflightRefused, preflight
from boxmunge.userns.shift import Direction
from boxmunge.userns.switch import (
    MigrationError, back_to_prior, daemon_json_path, ensure_prior, read_daemon_json,
    set_caddyfile_mode,
)
from boxmunge.userns.volumes import data_dir, move, recreate

COMPONENT = "userns-rollback"
_PLATFORM = frozenset({"caddy", "system"})


def _abort(paths: BoxPaths, j: Journal, daemon: DaemonControl, timers: TimerControl,
           images_dir: Path, save: Save) -> Journal:
    """Before the switch nothing was carried: restart what was stopped. Also
    from `started`: an undone switch journals it, yet a project whose restart
    failed during the undo is still down. Idempotent for running projects."""
    j.daemon_json = ensure_prior(paths, j.daemon_json, j.offset, daemon, j.daemon_json_owner)
    bring_up(paths, Inventory.from_json(j.inventory), j, save, component=COMPONENT,
             prefix="abort")
    remove_tars(images_dir)
    timers.restore(j.timers)
    clear_marker(paths)
    j.direction, j.phase, j.failed = ROLLBACK, "rolled-back", None
    save()
    report_back(paths, j, "abort", "userns migration abandoned before the switch", COMPONENT)
    return j


def _verify_prior_store(j: Journal) -> None:
    info = uo.docker_info()
    driver_type = dict(info.get("DriverStatus") or []).get("driver-type", "")
    got = (info.get("Driver"), driver_type, "name=userns" in (info.get("SecurityOptions") or []))
    want = (j.prior_store["driver"], j.prior_store["driver_type"], False)
    if got != want:
        raise MigrationError(f"the daemon came back as {got}, not the prior store {want}")


def _where(old_root: Path, name: str) -> str:
    """Where a volume of the remapped daemon goes back to: an old-root
    volume whose data left (`old`), one whose data never left (`stayed`:
    the migration stopped before moving it), or one made during the soak."""
    if not (old_root / "volumes" / name).is_dir():
        return "soak"
    return "stayed" if os.path.lexists(data_dir(old_root, name)) else "old"


def _unfinished(j: Journal, item: str, key: str) -> str | None:
    """The forward shift's setuid list, as a seed, only for a tree whose
    forward shift never finished: a kill inside it may have cleared a bit.
    A finished one's list is stale (the soak changed the tree since)."""
    return None if j.items.get(item) == "shifted" else key


def _restore_data(paths: BoxPaths, j: Journal, rinv: Inventory, finv: Inventory,
                  old_root: Path, new_root: Path, save: Save) -> None:
    for v in rinv.volumes:
        if v.anonymous:
            continue
        key = f"rb-volume:{v.name}"
        if j.items.get(key) is None:
            j.items[key] = _where(old_root, v.name)
            save()
        if j.items[key] == "old":
            move(new_root, old_root, v.name)
            j.items[key] = "moved"
            save()
        if j.items[key] == "moved":
            tree = data_dir(old_root, v.name)
            forward = str(data_dir(new_root, v.name))
            shift_journalled(j, tree, Direction.INVERSE, save, f"rb:{tree}",
                             seed=_unfinished(j, f"volume:{v.name}", forward))
            j.items[key] = "restored"
            save()
    for source in outermost(set(rinv.data_binds()) | set(finv.data_binds())):
        key = f"rb-bind:{source}"
        if j.items.get(key) != "restored" and os.path.lexists(source):
            shift_journalled(j, Path(source), Direction.INVERSE, save, f"rb:{source}",
                             seed=_unfinished(j, f"bind:{source}", source))
            j.items[key] = "restored"
            save()
    if j.items.get("caddyfile") == "0644" and j.caddyfile_mode is not None \
            and j.items.get("rb-caddyfile") != "restored":
        set_caddyfile_mode(paths, j.caddyfile_mode)
        j.items["rb-caddyfile"] = "restored"
        save()


def _soak_volumes(j: Journal, rinv: Inventory, old_root: Path, new_root: Path,
                  save: Save) -> None:
    for v in rinv.volumes:
        key = f"rb-volume:{v.name}"
        if j.items.get(key) in ("soak", "soak-created"):
            recreate(v)  # again on a resume, as in the forward migration
            j.items[key] = "soak-created"
            save()
            move(new_root, old_root, v.name)
            j.items[key] = "soak-moved"
            save()
        if j.items.get(key) == "soak-moved":
            tree = data_dir(old_root, v.name)
            shift_journalled(j, tree, Direction.INVERSE, save, f"rb:{tree}")
            j.items[key] = "soak-restored"
            save()


def _remove_remapped_containers() -> None:
    """Nothing needs the remapped daemon's containers or networks again (the bring-up
    recreates from compose on the old daemon, and the remapped root goes).
    Removed, a reboot during the restore cannot have their restart policies
    start them on data that is only partly unshifted."""
    ids = _run(["docker", "ps", "-aq", "--no-trunc"], capture=True).stdout.split()
    if ids:
        _run(["docker", "rm", "-f", *ids], capture=True, timeout=900)
    # Its networks too, so no bridge of theirs outlives the remapped root.
    nets = _run(["docker", "network", "ls", "-q", "--filter", "type=custom"],
                capture=True).stdout.split()
    if nets:
        _run(["docker", "network", "rm", *nets], capture=True)


def _leftovers(paths: BoxPaths, j: Journal, save: Save) -> None:
    """Old-root containers of projects deleted during the soak were started
    by their restart policies; remove them (and their soak-only volumes)."""
    projects = set(load_registered_projects(paths))
    for c in take_inventory(paths).containers:
        if c.compose_project in projects | _PLATFORM:
            continue
        _run(["docker", "rm", "-f", c.id], capture=True)
        j.items[f"rb-removed:{c.name}"] = f"removed (compose project {c.compose_project or '-'})"
        save()
        for m in c.mounts:
            if m.type == "volume" and j.items.get(f"rb-volume:{m.name}") == "soak-restored":
                _run(["docker", "volume", "rm", m.name], capture=True)
                j.items[f"rb-removed:volume:{m.name}"] = "removed"
                save()


def _start(paths: BoxPaths, j: Journal, daemon: DaemonControl, images_dir: Path) -> Journal:
    """Inventory the remapped daemon and run the inverse preflight (again
    on every resume before the quiesce: the soak goes on until then)."""
    _refuse_soak_edit(j)
    if not daemon_answers():
        daemon.start()
    if uo.remap_offset(paths) != j.offset:
        raise MigrationError(f"the daemon is not remapped at offset {j.offset} as the journal "
                             f"says; see docker-userns in health")
    inv = take_inventory(paths)
    if j.rollback_inventory:
        inv = inv.with_running_from(Inventory.from_json(j.rollback_inventory))
    report = preflight(paths, inv, direction=ROLLBACK, offset=j.offset,
                       images_dir=images_dir, scan_images=False,
                       extra_binds=Inventory.from_json(j.inventory).data_binds())
    print(report.text())
    if not report.ok:
        raise PreflightRefused(report)
    if j.direction == FORWARD:
        j.direction, j.phase = ROLLBACK, "rb-started"
    j.rollback_inventory = inv.to_json()
    return j


def _refuse_soak_edit(j: Journal) -> None:
    """Putting the original daemon.json back would drop a change made to
    the migration's one during the soak, silently: the operator decides."""
    from boxmunge.userns.daemon_config import merged_daemon_json
    ours = merged_daemon_json(j.daemon_json.encode() if j.daemon_json is not None
                              else None).decode()
    if read_daemon_json() != ours:
        raise MigrationError(
            f"{daemon_json_path()} changed since the migration wrote it; rolling back puts "
            f"the original back and would drop that change. Make the same change to the "
            f"original too (the journal holds it), or put back the migration's own file, "
            f"then run userns-rollback again")


def _refuse(j: Journal | None) -> Journal:
    if j is None:
        raise MigrationError("there is no userns migration to roll back")
    if j.direction == FORWARD and (j.phase == "committed" or COMMIT_STARTED in j.items):
        raise MigrationError("the migration is committed (or its commit began): the old root "
                             "is gone, so it cannot be rolled back"
                             + ("; finish it with userns-commit" if j.phase != "committed"
                                else ""))
    if j.direction == ROLLBACK and j.phase == "rolled-back":
        raise MigrationError("the migration was already rolled back")
    return j


def _reverse(paths: BoxPaths, j: Journal, daemon: DaemonControl, timers: TimerControl,
             rb_images: Path, save: Save) -> None:
    rinv, finv = Inventory.from_json(j.rollback_inventory), Inventory.from_json(j.inventory)
    old_root = Path(finv.root)
    new_root = old_root / f"{j.offset}.{j.offset}"
    if not j.reached("rb-quiesced"):
        # Again on a resume: the fresh inventory may hold an image made since.
        save_all(rinv.images, j, rb_images, save, prefix="rb-image")
        j.phase = "rb-saved"
        save()
        set_marker(paths, "userns-rollback")
        timers.stop_all()  # persistent: only once the marker says why
        quiesce(rinv)
        _remove_remapped_containers()
        daemon.stop()
        j.phase = "rb-quiesced"
        save()
    if not j.reached("rb-restored"):
        daemon.stop()  # again on a resume: a reboot starts the remapped daemon
        _restore_data(paths, j, rinv, finv, old_root, new_root, save)
        j.phase = "rb-restored"
        save()
    if not j.reached("rb-switched"):
        back_to_prior(paths, j.daemon_json, j.offset, daemon, j.daemon_json_owner)
        _verify_prior_store(j)
        j.phase = "rb-switched"
        save()
    if not daemon_answers():
        daemon.start()
    if not j.reached("rb-rebuilt"):
        _soak_volumes(j, rinv, old_root, new_root, save)
        load_all(rinv.images, j, rb_images, save, prefix="rb-image")
        _leftovers(paths, j, save)
        j.phase = "rb-rebuilt"
        save()
    bring_up(paths, rinv, j, save, component=COMPONENT, prefix="rb-project")
    if new_root.is_dir() and not new_root.is_symlink():
        shutil.rmtree(new_root)


def rollback(paths: BoxPaths, *, daemon: DaemonControl, timers: TimerControl,
             images_dir: Path = IMAGES_DIR) -> Journal:
    """Undo an uncommitted or interrupted migration. Caller: root with upgrade.lock."""
    j = _refuse(load_journal(paths))
    journal = j

    def save() -> None:
        save_journal(paths, journal)

    with project_locks(paths, sorted(load_registered_projects(paths))):
        aborting = j.direction == FORWARD and not j.reached("switched")
        if not aborting and (j.direction == FORWARD or not j.reached("rb-quiesced")):
            _start(paths, j, daemon, images_dir)
            save()
        try:
            j.failed = None
            if aborting:
                return _abort(paths, j, daemon, timers, images_dir, save)
            _reverse(paths, j, daemon, timers, images_dir / "rollback", save)
            remove_tars(images_dir)
            timers.restore(j.timers)
            clear_marker(paths)
            j.phase = "rolled-back"
            save()
        except BaseException as e:
            j.failed = f"{j.phase}: {e}"
            save()
            held = ("The marker is set, so every project command refuses, and the boxmunge "
                    "timers stay stopped. " if migration_in_progress(paths) else "")
            notify(paths, "userns rollback stopped", f"Stopped after {j.phase}: {e}. {held}"
                   f"Fix the cause, then re-run userns-rollback to resume.",
                   component=COMPONENT, priority=1)
            raise
    report_back(paths, j, "rb-project", "userns migration rolled back", COMPONENT)
    return j
