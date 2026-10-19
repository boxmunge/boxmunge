# SPDX-License-Identifier: Apache-2.0
"""The forward migration (spec section 5): journalled, every step resumable.

Phase 0 (inventory and preflight) runs again under the locks on every
resume before the daemon switch, after making sure the old daemon runs on
its original config. Phase 1 prepares with no downtime (identity, one tar
per image, PREMIGRATE backups synced off-site). Phase 2 stops everything
and switches the daemon; a remapped daemon that will not start puts the
original daemon.json back and restarts everything on the untouched old
root. Phase 3 rebuilds the daemon's state (network, images, the Caddyfile's
mode, volumes moved and shifted, bind data shifted). Phase 4 brings the box
up project by project, then the timers come back and the journal says
`applied`. Each step is journalled (durably) before the next starts, so a
kill at any point leaves a box that still runs unremapped or that a rerun
completes, or userns-rollback reverses. Any failure is journalled, alerted
and left for the operator.
"""
from __future__ import annotations

import os
import sys
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

from boxmunge.docker_run import run as _run
from boxmunge.fileutil import project_lock
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import load_registered_projects
from boxmunge.userns import offset as uo
from boxmunge.userns.bringup import bring_up, quiesce
from boxmunge.userns.steps import _backups, _final, disk_before_downtime
from boxmunge.userns.daemon_ctl import DaemonControl, TimerControl, daemon_answers
from boxmunge.userns.images import IMAGES_DIR, load_all, save_all
from boxmunge.userns.inventory import PROXY_NETWORK, Inventory, take_inventory
from boxmunge.userns.marker import clear_marker, set_marker
from boxmunge.userns.journal import FORWARD, ROLLBACK, Journal, load_journal, save_journal
from boxmunge.userns.preflight import PreflightRefused, preflight
from boxmunge.userns.shift import Direction, scan_tree, shift_tree
from boxmunge.userns.switch import (
    CADDYFILE_MODE, MigrationError, back_to_prior, caddyfile_mode, create_identity,
    daemon_json_owner,
    ensure_prior, host_ids, prior_store, read_daemon_json, set_caddyfile_mode, to_remapped,
)
from boxmunge.userns.volumes import data_dir, move, recreate

COMPONENT = "userns-migrate"
FINISH = "userns-migrate (to resume) or userns-rollback"


class SwitchUndone(MigrationError):
    """The remapped daemon did not start; the box runs on its old root again."""
Save = Callable[[], None]


@contextmanager
def project_locks(paths: BoxPaths, projects: list[str]) -> Iterator[None]:
    """Every project lock, in name order. The migration is the only holder of
    more than one (it runs under upgrade.lock); see fileutil's lock order."""
    with ExitStack() as stack:
        for p in sorted(projects):
            stack.enter_context(project_lock(p, paths))
        yield


def shift_journalled(j: Journal, tree: Path, direction: Direction, save: Save,
                     key: str, seed: str | None = None) -> None:
    """Journal the tree's setuid list, then shift it (shift.py's docstring).
    `seed` is the key of the same tree's earlier shift the other way, whose
    list holds a mode a kill inside it may have cleared. Ids already in the
    target range are accepted only once a shift of this tree has begun."""
    resumed = key in j.setid
    setid = {**j.setid.get(seed or "", {}), **scan_tree(tree, j.offset, direction).setid,
             **j.setid.get(key, {})}
    if not resumed or setid != j.setid[key]:
        j.setid[key] = setid  # also the mark that this tree's shift has begun
        save()
    shift_tree(tree, j.offset, direction, setid, resumed=resumed)


def _phase0(paths: BoxPaths, j: Journal | None, timers: TimerControl,
            images_dir: Path) -> Journal:
    s = j.offset if j is not None else uo.allocate_offset(uo.ETC, host_ids())
    inv = take_inventory(paths)
    if j is not None and j.inventory:
        inv = inv.with_running_from(Inventory.from_json(j.inventory))
    report = preflight(paths, inv, direction=FORWARD, offset=s, images_dir=images_dir)
    print(report.text())
    if not report.ok:
        raise PreflightRefused(report)
    if j is None:
        return Journal(FORWARD, "started", s, daemon_json=read_daemon_json(),
                       daemon_json_owner=daemon_json_owner(),
                       prior_store=prior_store(inv), inventory=inv.to_json(),
                       timers=timers.state(), caddyfile_mode=caddyfile_mode(paths))
    j.inventory = inv.to_json()
    return j


def _prepare(paths: BoxPaths, j: Journal, inv: Inventory, save: Save) -> None:
    create_identity(j.offset)
    _backups(paths, inv)
    j.phase = "prepared"
    save()


def _switch(paths: BoxPaths, j: Journal, inv: Inventory, daemon: DaemonControl,
            timers: TimerControl, save: Save) -> None:
    try:
        to_remapped(paths, j.daemon_json, j.offset, daemon, inv.bridges)
        if uo.remap_offset(paths) != j.offset:
            raise MigrationError("the daemon came up with another offset")
    except Exception as e:
        back_to_prior(paths, j.daemon_json, j.offset, daemon, j.daemon_json_owner)
        for key in [k for k in j.items if k.startswith("restart:")]:
            del j.items[key]  # an earlier failed switch's restart says nothing about this one
        bring_up(paths, inv, j, save, component=COMPONENT, prefix="restart")
        timers.restore(j.timers)
        clear_marker(paths)  # nothing was carried: the box is as before
        # Back before "prepared": the box runs for however long the operator
        # takes, so the next attempt makes its PREMIGRATE backups afresh.
        j.phase, j.failed = "started", f"the remapped daemon did not start: {e}"
        save()
        raise SwitchUndone(f"the remapped daemon did not start ({e}). daemon.json was "
                             f"restored and the box restarted on its old root; fix the cause, "
                             f"then run userns-migrate again, or userns-rollback") from e
    j.phase = "switched"
    save()


def _network(inv: Inventory) -> None:
    found = _run(["docker", "network", "ls", "-q", "--filter", f"name=^{PROXY_NETWORK}$"],
                 capture=True).stdout.split()
    if found:
        return  # created before a crash
    net = inv.network
    args = ["docker", "network", "create", "--driver", str(net.get("driver") or "bridge")]
    for cfg in (net.get("ipam") or {}).get("Config") or []:
        for key, flag in (("Subnet", "--subnet"), ("Gateway", "--gateway"),
                          ("IPRange", "--ip-range")):
            if cfg.get(key):
                args += [flag, cfg[key]]
    for k, v in sorted((net.get("options") or {}).items()):
        args += ["--opt", f"{k}={v}"]
    for k, v in sorted((net.get("labels") or {}).items()):
        args += ["--label", f"{k}={v}"]
    _run([*args, PROXY_NETWORK], capture=True)


def _rebuild(paths: BoxPaths, j: Journal, inv: Inventory, images_dir: Path, save: Save) -> None:
    old_root = Path(inv.root)
    new_root = old_root / f"{j.offset}.{j.offset}"
    if j.items.get("network") != "created":
        _network(inv)
        j.items["network"] = "created"
        save()
    load_all(inv.images, j, images_dir, save)
    if j.caddyfile_mode is not None and j.items.get("caddyfile") != "0644":
        set_caddyfile_mode(paths, CADDYFILE_MODE)
        j.items["caddyfile"] = "0644"
        save()
    for v in inv.volumes:
        if v.anonymous:
            continue  # empty ones are recreated empty; ones with data were refused
        key = f"volume:{v.name}"
        if j.items.get(key) not in ("moved", "shifted"):
            recreate(v)  # again on a resume: a restarted daemon may have dropped it
            j.items[key] = "created"
            save()
            move(old_root, new_root, v.name)
            j.items[key] = "moved"
            save()
        if j.items[key] == "moved":
            tree = data_dir(new_root, v.name)
            shift_journalled(j, tree, Direction.FORWARD, save, str(tree))
            j.items[key] = "shifted"
            save()
    for source in inv.data_binds():
        key = f"bind:{source}"
        if j.items.get(key) != "shifted" and os.path.lexists(source):
            shift_journalled(j, Path(source), Direction.FORWARD, save, source)
            j.items[key] = "shifted"
            save()
    j.phase = "rebuilt"
    save()


def _ensure_remapped(paths: BoxPaths, j: Journal, daemon: DaemonControl) -> None:
    """After the switch: the remapped daemon runs, exactly as journalled."""
    if not daemon_answers():
        daemon.start()
    if uo.remap_offset(paths) != j.offset:
        raise MigrationError(f"the daemon is not remapped at offset {j.offset} as the journal "
                             f"says; see docker-userns in health")


def _refuse_rerun(j: Journal | None) -> Journal | None:
    if j is not None and j.direction == FORWARD and j.phase in ("applied", "committed"):
        raise MigrationError(f"the migration is already {j.phase}; "
                             + ("nothing to do" if j.phase == "committed"
                                else "soak, then userns-commit, or userns-rollback"))
    if j is not None and j.direction == ROLLBACK and j.phase != "rolled-back":
        raise MigrationError(f"a rollback stopped at {j.phase}; finish it with userns-rollback")
    if j is not None and j.direction == ROLLBACK:
        return None  # a rolled-back box starts over from phase 0
    return j


def migrate(paths: BoxPaths, *, daemon: DaemonControl, timers: TimerControl,
            images_dir: Path = IMAGES_DIR) -> Journal:
    """Run or resume the migration. Caller: root, holding upgrade.lock."""
    j = _refuse_rerun(load_journal(paths))
    with project_locks(paths, sorted(load_registered_projects(paths))):
        if j is not None and not j.reached("switched"):
            prior = ensure_prior(paths, j.daemon_json, j.offset, daemon, j.daemon_json_owner)
            if prior != j.daemon_json:  # the operator's fix, kept with its own mode
                j.daemon_json, j.daemon_json_owner = prior, daemon_json_owner()
            save_journal(paths, j)
        elif j is not None:
            _ensure_remapped(paths, j, daemon)
        if j is None or not j.reached("switched"):
            j = _phase0(paths, j, timers, images_dir)
            save_journal(paths, j)
        journal = j

        def save() -> None:
            save_journal(paths, journal)

        inv = Inventory.from_json(j.inventory)
        stopped = False  # the timers, as this run left them
        try:
            j.failed = None
            if not j.reached("switched"):
                save_all(inv.images, j, images_dir, save)
                if not j.reached("prepared"):
                    _prepare(paths, j, inv, save)
                disk_before_downtime(inv, images_dir)
            # From here until the box runs again: no timer, no project command.
            set_marker(paths, FINISH)
            timers.stop_all()
            stopped = True
            if not j.reached("switched"):
                quiesce(inv)  # again on a resume: the old daemon may have restarted some
                j.phase = "quiesced"
                save()
                try:
                    _switch(paths, j, inv, daemon, timers, save)
                except SwitchUndone:
                    stopped = False  # the box runs on its old root, timers too
                    raise
            if not j.reached("rebuilt"):
                _rebuild(paths, j, inv, images_dir, save)
            results = bring_up(paths, inv, j, save, component=COMPONENT)
            timers.restore(j.timers)
            stopped = False
            clear_marker(paths)
            j.phase, j.failed = "applied", None
            j.applied_at = datetime.now(timezone.utc).isoformat()
            save()
        except BaseException as e:
            j.failed = j.failed or f"{j.phase}: {e}"
            save()
            held = ("The boxmunge timers are stopped, and every project command refuses "
                    "until it is finished. " if stopped else "")
            notify(paths, "userns migration stopped", f"Stopped after phase {j.phase}: {e}. "
                   f"{held}Re-run userns-migrate to resume, or userns-rollback.",
                   component=COMPONENT, priority=1)
            raise
    try:
        _final(paths, j, results)  # outside the locks: the scan and check-all take them
    except Exception as e:  # the migration is applied; only its report is missing
        print(f"ERROR: the migration is applied, but its final checks failed: {e}. Run "
              f"check-all, security scan and self-test yourself.", file=sys.stderr)
        notify(paths, "userns migration applied; its final checks failed", str(e),
               component=COMPONENT, priority=1)
    return j

