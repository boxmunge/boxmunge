# SPDX-License-Identifier: Apache-2.0
"""What the migration changes outside Docker's data: daemon.json, the userns
record, the remap identity, and the Caddyfile's mode.

Each write is atomic and idempotent, so a resumed migration or rollback
repeats it safely. The daemon is switched by stopping it, writing both
sources and starting it again; `back_to_prior` puts the original
daemon.json back byte for byte and removes the record.
"""
from __future__ import annotations

import grp
import os
import pwd
import shutil
import stat
import subprocess
from pathlib import Path

from boxmunge.fileutil import atomic_write_bytes, fsync_dir
from boxmunge.paths import BoxPaths
from boxmunge.userns import offset as uo
from boxmunge.userns.daemon_config import (
    MANAGED_CONTAINERD, SYSTEM_CONTAINERD, SYSTEM_CONTAINERD_ROOT,
)
from boxmunge.userns.daemon_ctl import DaemonControl, daemon_answers
from boxmunge.userns.inventory import CONTAINERD_STORE, Inventory
from boxmunge.userns.preflight_checks import dir_size
from boxmunge.userns.shift import mount_points_under
from boxmunge.userns.walk import open_parent_nofollow

_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
CADDYFILE_MODE = 0o644


class MigrationError(Exception):
    """The migration cannot start or continue; the message says what to do."""


def remove_docker_tree(root: Path) -> None:
    """shutil.rmtree, refused while anything is mounted below `root`: rmtree
    crosses filesystems, so a leaked overlay `merged` or `shm` mount would
    have its contents deleted through it."""
    mounts = mount_points_under(root)
    if mounts:
        raise MigrationError(
            f"{root} has mounts below it ({', '.join(mounts[:5])}"
            f"{', ...' if len(mounts) > 5 else ''}), so it is not deleted: deleting it would "
            f"delete through them. Unmount each as root (umount <path>), then run the "
            f"command again")
    shutil.rmtree(root)


def daemon_json_path() -> Path:
    return uo.ETC / "docker" / "daemon.json"


def read_daemon_json() -> str | None:
    path = daemon_json_path()
    try:
        fd = os.open(path, _OPEN)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        return f.read().decode()


def daemon_json_owner() -> list[int] | None:
    """[mode, uid, gid] of daemon.json, or None when there is none."""
    try:
        st = os.lstat(daemon_json_path())
    except FileNotFoundError:
        return None
    return [stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid]


def write_daemon_json(text: str | None, owner: list[int] | None = None) -> None:
    """`owner`: the original's [mode, uid, gid] when it is put back; the
    migration's own file is root's 0644 (deploy reads userns-remap in it)."""
    path = daemon_json_path()
    if text is None:
        if os.path.lexists(path):
            os.unlink(path)
            fsync_dir(path.parent)
        return
    if not os.path.lexists(path.parent):
        # Made here, root's 0755: atomic_write_bytes would hand a directory
        # it creates to deploy, who could then rewrite the daemon's config.
        os.mkdir(path.parent, 0o755)
        fsync_dir(path.parent.parent)
    mode, uid, gid = owner or [0o644, os.geteuid(), os.getegid()]
    atomic_write_bytes(path, text.encode(), mode=mode, owner=(uid, gid))


def host_ids() -> set[int]:
    return {p.pw_uid for p in pwd.getpwall()} | {g.gr_gid for g in grp.getgrall()}


def _checked(cmd: list[str]) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise MigrationError(f"{' '.join(cmd)} failed: {result.stderr.strip()}")


def create_identity(s: int) -> None:
    """boxmunge-remap and its one range S..S+65535 in both subid files."""
    if subprocess.run(["id", uo.REMAP_NAME], capture_output=True, check=False).returncode != 0:
        _checked(["useradd", "--system", "--user-group", "--no-create-home", "--shell",
                  "/usr/sbin/nologin", uo.REMAP_NAME])
    try:
        grp.getgrnam(uo.REMAP_NAME)
    except KeyError:
        raise MigrationError(f"user {uo.REMAP_NAME} exists without a group of that name; "
                             f"Docker needs both. Create it: groupadd --system "
                             f"{uo.REMAP_NAME}") from None
    uids, gids = uo.remap_ranges(uo.ETC)
    if not uids and not gids:
        for name in ("subuid", "subgid"):  # usermod refuses to add to a missing file
            path = uo.ETC / name
            if not os.path.lexists(path):
                atomic_write_bytes(path, b"", mode=0o644, owner=(0, 0))
        span = f"{s}-{s + uo.RANGE - 1}"
        _checked(["usermod", "--add-subuids", span, "--add-subgids", span, uo.REMAP_NAME])
    uids, gids = uo.remap_ranges(uo.ETC)
    want = [(s, uo.RANGE)]
    if [(r.start, r.count) for r in uids] != want or [(r.start, r.count) for r in gids] != want:
        raise MigrationError(f"{uo.REMAP_NAME}'s subordinate ids are {uids} / {gids}, not "
                             f"{s}-{s + uo.RANGE - 1} in both /etc/subuid and /etc/subgid")


def require_remapped(paths: BoxPaths, s: int) -> None:
    """After the switch, every command acts only on the daemon the journal
    describes: the remapped one, at the journalled offset."""
    if uo.remap_offset(paths) != s:
        raise MigrationError(f"the daemon is not remapped at offset {s} as the journal "
                             f"says; see docker-userns in health")


def store_size(prior: dict, root: Path) -> int:
    """Bytes the old daemon's store holds under its root `root`: what phase
    0 journals as the prior store's size, and what commit must free."""
    if prior["driver_type"] == CONTAINERD_STORE:
        return dir_size(Path(prior["store_root"]))
    return dir_size(root / "overlay2") + dir_size(root / "image")


def prior_store(inv: Inventory) -> dict:
    """The store the old daemon used, and its size, for commit and rollback."""
    root = Path(inv.root)
    prior = {"driver": inv.driver, "driver_type": inv.driver_type,
             "store_root": str(root / "overlay2")}
    if inv.driver_type == CONTAINERD_STORE:
        # As the daemon reports it (the preflight refused any other):
        # dockerd's own containerd keeps its root in the daemon's root (and a
        # remapped daemon's in the remapped root); the system containerd is
        # shared by both daemons.
        address, namespace = inv.containerd_address, inv.containerd_namespace
        if address in MANAGED_CONTAINERD:
            managed, croot = True, root / "containerd" / "daemon"
        elif address in SYSTEM_CONTAINERD:
            managed, croot = False, Path(SYSTEM_CONTAINERD_ROOT)
        else:
            raise MigrationError(f"the daemon uses containerd at {address!r}, which the "
                                 f"migration does not support (see userns-migrate --check)")
        prior.update(store_root=str(croot),
                     containerd={"address": address, "namespace": namespace}, managed=managed)
    return {**prior, "size": store_size(prior, root)}


_SYS_NET = Path("/sys/class/net")


def drop_bridges(names: list[str]) -> None:
    """Delete a stopped daemon's bridge interfaces, as a reboot would (the
    daemon makes them again when it starts). Left in place, each keeps its
    subnet's route, and the next daemon's bridge for the same subnet (the
    proxy network is recreated with its recorded subnet) would sit behind
    a second route the kernel may prefer: published ports would break."""
    for name in names:
        if not os.path.lexists(_SYS_NET / name):
            continue
        result = subprocess.run(["ip", "link", "delete", name], capture_output=True, text=True,
                                check=False)
        if result.returncode != 0:
            raise MigrationError(f"ip link delete {name} failed: {result.stderr.strip()}")


def _merged(daemon_json: str | None) -> str:
    """This migration's daemon.json: the original with the remap merged in."""
    from boxmunge.userns.daemon_config import merged_daemon_json
    return merged_daemon_json(daemon_json.encode() if daemon_json is not None else None).decode()


def switch_interrupted(paths: BoxPaths, daemon_json: str | None) -> bool:
    """Did a switch to the remapped daemon begin and was not undone, given
    the journalled original `daemon_json`? to_remapped writes the merged
    daemon.json, then the record; back_to_prior writes the original, then
    drops the record: a kill between the two leaves either one alone. The
    resume puts the old daemon back first (ensure_prior); --check says so."""
    return read_daemon_json() == _merged(daemon_json) or uo.recorded_offset(paths) is not None


def to_remapped(paths: BoxPaths, daemon_json: str | None, s: int, daemon: DaemonControl,
                bridges: list[str]) -> None:
    """Stop the daemon, write the merged daemon.json and the record, start it."""
    daemon.stop()
    drop_bridges(bridges)
    write_daemon_json(_merged(daemon_json))
    uo.write_offset_record(paths, s)
    daemon.start()


def back_to_prior(paths: BoxPaths, daemon_json: str | None, s: int,
                  daemon: DaemonControl, owner: list[int] | None = None) -> None:
    """Stop the daemon, put the original daemon.json back (with its mode and
    owner), drop the record, start it."""
    daemon.stop()
    write_daemon_json(daemon_json, owner)
    uo.remove_offset_record(paths, s)
    daemon.start()


def ensure_prior(paths: BoxPaths, daemon_json: str | None, s: int,
                 daemon: DaemonControl, owner: list[int] | None = None) -> str | None:
    """Before the switch completed: the old daemon runs on its prior config.

    A crash inside the switch left the merged daemon.json (this migration's
    own write: put back) or the record, or a stopped daemon. A daemon.json
    the operator changed since (to fix why the remapped daemon would not
    start) becomes the prior config, unless it still names a userns remap.
    Returns the prior config to journal."""
    from boxmunge.userns.daemon_config import parse_daemon_json
    journalled, now = daemon_json, read_daemon_json()
    if now not in (journalled, _merged(journalled)):
        if parse_daemon_json(now.encode() if now is not None else None).get("userns-remap"):
            raise MigrationError(f"{daemon_json_path()} changed since the migration began and "
                                 f"names a userns-remap; put back the original (the journal "
                                 f"holds it) or remove the remap from it, then run this again")
        print(f"  {daemon_json_path()} changed since the migration began; using it as the "
              f"prior config")
        daemon_json = now
    if switch_interrupted(paths, journalled):
        back_to_prior(paths, daemon_json, s, daemon, owner)
    elif not daemon_answers():
        daemon.start()
    return daemon_json


def _caddyfile_fd(paths: BoxPaths) -> int:
    parent, name = open_parent_nofollow(paths.caddyfile)
    try:
        fd = os.open(name, _OPEN, dir_fd=parent)
    finally:
        os.close(parent)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise MigrationError(f"{paths.caddyfile} is not a regular file")
    return fd


def caddyfile_mode(paths: BoxPaths) -> int | None:
    try:
        fd = _caddyfile_fd(paths)
    except FileNotFoundError:
        return None
    try:
        return stat.S_IMODE(os.fstat(fd).st_mode)
    finally:
        os.close(fd)


def set_caddyfile_mode(paths: BoxPaths, mode: int) -> None:
    fd = _caddyfile_fd(paths)
    try:
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
