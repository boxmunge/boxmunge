# SPDX-License-Identifier: Apache-2.0
"""userns-commit: after the soak, delete the old root and the old images.

On the containerd store kept by dockerd's own containerd, the remapped
daemon runs its own containerd from the remapped root, so the old one's
root is a directory nothing uses any more, and it goes. With the system
containerd, shared by both daemons, removing the images alone frees
nothing: the old containers' leases and their `<id>-init`/rootfs snapshots
still pin content. So leases go first, then snapshots (children before
parents), then images (the remapped daemon, on overlay2, keeps none of
them in containerd). Either way the store's size must have fallen by at
least the old store's inventoried size, less 10%. On a graph driver,
overlay2/ and image/ go.
The size before is journalled when the commit starts, so a resumed commit
measures against the same figure. Once committed, rollback is no longer
offered.
"""
from __future__ import annotations

import shutil
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from boxmunge.commands.check import run_check
from boxmunge.docker_run import run as _run
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import deployed_among, load_registered_projects
from boxmunge.userns import offset as uo
from boxmunge.userns.images import IMAGES_DIR, remove_tars
from boxmunge.userns.inventory import CONTAINERD_STORE, Inventory
from boxmunge.userns.journal import FORWARD, Journal, load_journal, save_journal
from boxmunge.userns.preflight_checks import dir_size
from boxmunge.userns.switch import MigrationError

SOAK = timedelta(hours=48)
_GC_WAIT = 120
_OLD_ROOT_DIRS = ("containers", "volumes", "image")


def _old_store_size(prior: dict, old_root: Path) -> int:
    """The old store as phase 0 measured it (switch.prior_store)."""
    if prior["driver_type"] == CONTAINERD_STORE:
        return dir_size(Path(prior["store_root"]))
    return dir_size(old_root / "overlay2") + dir_size(old_root / "image")


def _ctr(prior: dict, *args: str) -> str:
    return _run(["ctr", "--address", prior["containerd_address"], "-n", prior["namespace"], *args],
                capture=True, timeout=600).stdout


def snapshot_removal_order(listing: str) -> list[str]:
    """Snapshot keys, children before their parents, from `ctr snapshots ls`."""
    parent = {}
    for line in listing.splitlines()[1:]:
        cols = line.split()
        if cols:
            parent[cols[0]] = cols[1] if len(cols) > 2 else ""
    order, remaining = [], dict(parent)
    while remaining:
        leaves = sorted(k for k in remaining if k not in remaining.values())
        if not leaves:
            raise MigrationError(f"snapshot parents form a cycle: {sorted(remaining)}")
        order += leaves
        for k in leaves:
            del remaining[k]
    return order


def _clean_containerd(prior: dict) -> None:
    for lease in _ctr(prior, "leases", "ls", "-q").split():
        _ctr(prior, "leases", "rm", lease)
    listing = _ctr(prior, "snapshots", "--snapshotter", "overlayfs", "ls")
    for key in snapshot_removal_order(listing):
        _ctr(prior, "snapshots", "--snapshotter", "overlayfs", "rm", key)
    images = _ctr(prior, "images", "ls", "-q").split()
    if images:
        _ctr(prior, "images", "rm", *images)


def _drop_managed_root(old_root: Path, s: int, store_root: Path) -> None:
    """dockerd's own old containerd root, once its remapped one is in use."""
    if not (old_root / f"{s}.{s}" / "containerd" / "daemon").is_dir():
        raise MigrationError(f"the remapped daemon's containerd root is not under "
                             f"{old_root}/{s}.{s}; {store_root} may still be in use, so it "
                             f"is left as it is")
    if store_root.is_dir() and not store_root.is_symlink():
        shutil.rmtree(store_root)


def _checked(paths: BoxPaths, j: Journal | None, now: datetime) -> Journal:
    if j is None or j.direction != FORWARD or j.phase != "applied":
        raise MigrationError(f"nothing to commit (journal: "
                             f"{'none' if j is None else f'{j.direction} {j.phase}'})")
    applied = datetime.fromisoformat(str(j.applied_at))
    if now - applied < SOAK:
        raise MigrationError(f"soak until {(applied + SOAK).isoformat()} before committing")
    if uo.remap_offset(paths) != j.offset:
        raise MigrationError("the daemon is not remapped as the journal says; see "
                             "docker-userns in health")
    projects = deployed_among(load_registered_projects(paths), paths)
    unhealthy = [p for p in projects if run_check(p, paths, verbose=False) != 0]
    if unhealthy:
        raise MigrationError(f"not every project is healthy: {', '.join(unhealthy)}")
    return j


def commit(paths: BoxPaths, *, now: datetime | None = None,
           images_dir: Path = IMAGES_DIR) -> Journal:
    j = _checked(paths, load_journal(paths), now or datetime.now(timezone.utc))
    prior = j.prior_store
    old_root = Path(Inventory.from_json(j.inventory).root)
    if "commit-before" not in j.items:
        j.items["commit-before"] = str(_old_store_size(prior, old_root))
        save_journal(paths, j)
    before = int(j.items["commit-before"])
    remove_tars(images_dir)
    for sub in _OLD_ROOT_DIRS:
        if (old_root / sub).is_dir() and not (old_root / sub).is_symlink():
            shutil.rmtree(old_root / sub)
    if prior["driver_type"] == CONTAINERD_STORE and prior["managed"]:
        _drop_managed_root(old_root, j.offset, Path(prior["store_root"]))
    elif prior["driver_type"] == CONTAINERD_STORE:
        _clean_containerd(prior)
    elif Path(prior["store_root"]).is_dir():
        shutil.rmtree(prior["store_root"])
    deadline = time.monotonic() + _GC_WAIT
    while True:  # containerd reclaims content in its own garbage collection
        freed = before - _old_store_size(prior, old_root)
        if freed >= 0.9 * prior["size"] or time.monotonic() > deadline:
            break
        time.sleep(5)
    if freed < 0.9 * prior["size"]:
        raise MigrationError(f"only {freed} bytes were freed under {prior['store_root']}, not "
                             f"the old store's {prior['size']} (less 10%); inspect what is "
                             f"left, then run userns-commit again")
    j.phase = "committed"
    save_journal(paths, j)
    return j
