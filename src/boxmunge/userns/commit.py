# SPDX-License-Identifier: Apache-2.0
"""userns-commit: after the soak, delete the old root and the old images.

On the containerd store kept by dockerd's own containerd, the remapped
daemon runs its own containerd from the remapped root, so the old one's
root is a directory nothing uses any more, and it goes. With the system
containerd, shared by both daemons, the old daemon's namespace (as phase 0
recorded it from docker info) is emptied through containerd's garbage
collector (_clean_containerd), and checked empty: that check is the proof,
since the store's size counts other namespaces, and blobs they share. On a
graph driver, overlay2/ and image/ go; there, and for dockerd's own
containerd, the store's size must have fallen by at least the old store's
inventoried size, less 10%. The size before is journalled when the commit
starts, so a resumed commit measures against the same figure. Once
committed, rollback is no longer offered.
"""
from __future__ import annotations

import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from boxmunge.commands.check import run_check
from boxmunge.docker_run import run as _run
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import deployed_among, load_registered_projects
from boxmunge.userns import offset as uo
from boxmunge.userns.durable import barrier
from boxmunge.userns.images import IMAGES_DIR, remove_tars
from boxmunge.userns.inventory import CONTAINERD_STORE, Inventory
from boxmunge.userns.journal import FORWARD, Journal, load_journal, save_journal
from boxmunge.userns.preflight_checks import dir_size
from boxmunge.userns.switch import MigrationError

COMPONENT = "userns-commit"
SOAK = timedelta(hours=48)
# Journalled before the first deletion: from then on there is no rollback.
COMMIT_STARTED = "commit-before"
_GC_LEASE = "boxmunge-userns-commit-gc"
_LISTINGS = {"containers": ("containers", "ls", "-q"), "images": ("images", "ls", "-q"),
             "leases": ("leases", "ls", "-q"), "content blobs": ("content", "ls", "-q")}
_SNAPSHOTTER = "io.containerd.snapshotter.v1"
_OLD_ROOT_DIRS = ("containers", "volumes", "image")


def _old_store_size(prior: dict, old_root: Path) -> int:
    """The old store as phase 0 measured it (switch.prior_store)."""
    if prior["driver_type"] == CONTAINERD_STORE:
        return dir_size(Path(prior["store_root"]))
    return dir_size(old_root / "overlay2") + dir_size(old_root / "image")


def _ctr(prior: dict, *args: str) -> str:
    c = prior["containerd"]
    return _run(["ctr", "--address", c["address"], "-n", c["namespace"], *args],
                capture=True, timeout=600).stdout


def _snapshotters(prior: dict) -> list[str]:
    """The snapshotters containerd loaded (`ctr plugins ls`: TYPE ID PLATFORMS STATUS)."""
    out = []
    for line in _ctr(prior, "plugins", "ls").splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 3 and cols[0] == _SNAPSHOTTER and cols[-1] == "ok":
            out.append(cols[1])
    if not out:
        raise MigrationError("containerd lists no snapshotter that loaded (ctr plugins ls)")
    return out


def _collect(prior: dict) -> None:
    """A synchronous garbage collection: deleting a lease with --sync waits
    for one, snapshotter and content cleanup included, even when the lease
    held nothing."""
    _ctr(prior, "leases", "create", "--id", _GC_LEASE)
    _ctr(prior, "leases", "rm", "--sync", _GC_LEASE)


def _left_in_namespace(prior: dict) -> dict[str, int]:
    """What the namespace still holds, by kind, with a count of each."""
    listed = {kind: _ctr(prior, *args).splitlines() for kind, args in _LISTINGS.items()}
    for name in _snapshotters(prior):
        # snapshots ls has no -q: its first line is a header
        listed[f"{name} snapshots"] = _ctr(prior, "snapshots", "--snapshotter", name,
                                           "ls").splitlines()[1:]
    left = {kind: sum(1 for line in lines if line.strip()) for kind, lines in listed.items()}
    return {kind: n for kind, n in left.items() if n}


def _clean_containerd(prior: dict) -> None:
    """Empty the old daemon's namespace by releasing what roots it (leases,
    images) and letting containerd collect the rest. Snapshots are not
    removed by name: dockerd releases a removed container's rootfs by
    deleting its lease, and the collector then deletes the container's
    snapshots without striking them from their parent's list of children,
    so every image a container was ever removed from refuses `ctr snapshots
    rm` ("cannot remove snapshot with child") for good. The collector does
    not read that list. Each step is idempotent, so a resumed commit runs
    them all again; the remapped daemon's namespace is never named."""
    for lease in _ctr(prior, "leases", "ls", "-q").split():
        _ctr(prior, "leases", "rm", lease)
    images = _ctr(prior, "images", "ls", "-q").split()
    if images:
        _ctr(prior, "images", "rm", *images)
    _collect(prior)
    left = _left_in_namespace(prior)
    if left:
        what = ", ".join(f"{n} {kind}" for kind, n in left.items())
        c = prior["containerd"]
        cmd = f"ctr --address {c['address']} -n {c['namespace']}"
        raise MigrationError(
            f"the old daemon's containerd namespace {c['namespace']} still holds {what} "
            f"after its leases and images were removed and containerd collected garbage: "
            f"something else still references them. Look with `{cmd} containers ls` (and "
            f"`snapshots --snapshotter <name> ls`, `content ls`), remove what holds them, "
            f"then run userns-commit again")


def _drop_managed_root(old_root: Path, s: int, store_root: Path) -> None:
    """dockerd's own old containerd root, once its remapped one is in use."""
    if not (old_root / f"{s}.{s}" / "containerd" / "daemon").is_dir():
        raise MigrationError(f"the remapped daemon's containerd root is not under "
                             f"{old_root}/{s}.{s}; {store_root} may still be in use, so it "
                             f"is left as it is")
    if store_root.is_dir() and not store_root.is_symlink():
        shutil.rmtree(store_root)


def _old_volumes_with_data(old_root: Path) -> list[str]:
    """Old-root volumes whose _data is still there and not empty: every
    carried volume's _data moved out of the old root."""
    volumes = old_root / "volumes"
    if not volumes.is_dir():
        return []
    left = []
    for entry in sorted(os.scandir(volumes), key=lambda e: e.name):
        data = Path(entry.path) / "_data"
        if entry.is_dir(follow_symlinks=False) and data.is_dir() and not data.is_symlink() \
                and any(os.scandir(data)):
            left.append(str(data))
    return left


def _check_containerd(prior: dict, info: dict, s: int) -> None:
    """The old daemon's containerd, as phase 0 recorded it, against the one
    the remapped daemon reports. The migration changed only the remap keys,
    so the remapped daemon must use the same containerd, in the namespace
    dockerd derives from the old one (moby-<s>.<s>); in the old namespace
    itself (containerd-namespace set), the commit would empty the live one."""
    if "containerd" not in prior:
        raise MigrationError(
            "this migration was journalled before boxmunge recorded the old daemon's "
            "containerd address and namespace (from docker info), and commit will not guess "
            "which namespace held the old images. Run userns-rollback, then userns-migrate "
            "again, and commit after its soak")
    old = prior["containerd"]
    live = info.get("Containerd") or {}
    address, namespace = live.get("Address"), (live.get("Namespaces") or {}).get("Containers")
    if address == old["address"] and namespace == old["namespace"]:
        raise MigrationError(
            f"the remapped daemon uses the old daemon's containerd namespace {namespace} "
            f"(containerd-namespace is set), so commit cannot tell the old images from the "
            f"live ones. Run userns-rollback, remove containerd-namespace from daemon.json or "
            f"dockerd's flags, and migrate again")
    want = f"{old['namespace']}-{s}.{s}"
    if (address, namespace) != (old["address"], want):
        raise MigrationError(
            f"the remapped daemon uses containerd at {address}, namespace {namespace}, not "
            f"{old['address']}, namespace {want} as the migration left it; daemon.json or "
            f"dockerd's flags changed during the soak. Put them back, or run userns-rollback")


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
    if j.prior_store["driver_type"] == CONTAINERD_STORE:
        _check_containerd(j.prior_store, uo.docker_info(), j.offset)
    left = _old_volumes_with_data(Path(Inventory.from_json(j.inventory).root))
    if left:
        raise MigrationError(
            f"volumes in the old root still hold data the migration did not carry: "
            f"{', '.join(left)}. Commit would delete them. Copy out what you need, then "
            f"delete their directories by hand, and run userns-commit again")
    projects = deployed_among(load_registered_projects(paths), paths)
    unhealthy = [p for p in projects if run_check(p, paths, verbose=False) != 0]
    if unhealthy:
        raise MigrationError(f"not every project is healthy: {', '.join(unhealthy)}")
    return j


def commit(paths: BoxPaths, *, now: datetime | None = None,
           images_dir: Path = IMAGES_DIR) -> Journal:
    """Delete the old root, after the soak; alert how it went. A refusal before
    anything is deleted (nothing to commit, still soaking, not healthy) is
    only the operator's answer, not an alert."""
    j = _checked(paths, load_journal(paths), now or datetime.now(timezone.utc))
    try:
        j = _commit(paths, j, images_dir)
    except BaseException as e:
        notify(paths, "userns commit stopped", f"{e}. Run userns-commit again once it is "
               f"fixed (if it began deleting the old root, there is no rollback any more)",
               component=COMPONENT, priority=1)
        raise
    notify(paths, "userns migration committed", "The old Docker root is deleted; rollback is "
           "no longer offered.", component=COMPONENT, priority=0)
    return j


def _check_freed(prior: dict, old_root: Path, before: int) -> None:
    """What was deleted as directories: the old store must have gone."""
    freed = before - _old_store_size(prior, old_root)
    if freed < 0.9 * prior["size"]:
        raise MigrationError(f"only {freed} bytes were freed under {prior['store_root']}, not "
                             f"the old store's {prior['size']} (less 10%); inspect what is "
                             f"left, then run userns-commit again")


def _commit(paths: BoxPaths, j: Journal, images_dir: Path) -> Journal:
    prior = j.prior_store
    old_root = Path(Inventory.from_json(j.inventory).root)
    if COMMIT_STARTED not in j.items:
        j.items[COMMIT_STARTED] = str(_old_store_size(prior, old_root))
        save_journal(paths, j)
    before = int(j.items[COMMIT_STARTED])
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
    if not (prior["driver_type"] == CONTAINERD_STORE and not prior["managed"]):
        _check_freed(prior, old_root, before)
    barrier(paths, j, images_dir)  # the deletions, before the journal says committed
    j.phase = "committed"
    save_journal(paths, j)
    return j
