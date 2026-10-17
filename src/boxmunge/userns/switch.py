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
import stat
import subprocess
from pathlib import Path

from boxmunge.fileutil import atomic_write_bytes, fsync_dir
from boxmunge.paths import BoxPaths
from boxmunge.userns import offset as uo
from boxmunge.userns.daemon_ctl import DaemonControl, daemon_answers
from boxmunge.userns.inventory import CONTAINERD_STORE, Inventory
from boxmunge.userns.preflight_checks import dir_size
from boxmunge.userns.walk import open_parent_nofollow

_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
CADDYFILE_MODE = 0o644


class MigrationError(Exception):
    """The migration cannot start or continue; the message says what to do."""


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


def write_daemon_json(text: str | None) -> None:
    path = daemon_json_path()
    if text is None:
        if os.path.lexists(path):
            os.unlink(path)
            fsync_dir(path.parent)
        return
    # 0644: deploy reads userns-remap from it (offset.daemon_json_userns).
    atomic_write_bytes(path, text.encode(), mode=0o644, owner=(os.geteuid(), os.getegid()))


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


def prior_store(inv: Inventory) -> dict:
    """The store the old daemon used, and its size, for commit and rollback."""
    root = Path(inv.root)
    if inv.driver_type == CONTAINERD_STORE:
        # dockerd's own containerd keeps its root in the daemon's root (and a
        # remapped daemon's in the remapped root); the system containerd is
        # shared by both daemons.
        managed = (root / "containerd" / "daemon").is_dir()
        croot = root / "containerd" / "daemon" if managed else Path("/var/lib/containerd")
        address = ("/var/run/docker/containerd/containerd.sock" if managed
                   else "/run/containerd/containerd.sock")
        return {"driver": inv.driver, "driver_type": inv.driver_type, "store_root": str(croot),
                "containerd_address": address, "namespace": "moby", "managed": managed,
                "size": dir_size(croot)}
    return {"driver": inv.driver, "driver_type": inv.driver_type,
            "store_root": str(root / "overlay2"),
            "size": dir_size(root / "overlay2") + dir_size(root / "image")}


def to_remapped(paths: BoxPaths, daemon_json: str | None, s: int,
                daemon: DaemonControl) -> None:
    """Stop the daemon, write the merged daemon.json and the record, start it."""
    from boxmunge.userns.daemon_config import merged_daemon_json
    daemon.stop()
    merged = merged_daemon_json(daemon_json.encode() if daemon_json is not None else None)
    write_daemon_json(merged.decode())
    uo.write_offset_record(paths, s)
    daemon.start()


def back_to_prior(paths: BoxPaths, daemon_json: str | None, s: int,
                  daemon: DaemonControl) -> None:
    """Stop the daemon, put the original daemon.json back, drop the record, start it."""
    daemon.stop()
    write_daemon_json(daemon_json)
    uo.remove_offset_record(paths, s)
    daemon.start()


def ensure_prior(paths: BoxPaths, daemon_json: str | None, s: int,
                 daemon: DaemonControl) -> bool:
    """Before the switch completed: the old daemon runs on its original
    config. A crash inside the switch left the merged daemon.json or the
    record, or a stopped daemon. Returns True when the daemon was restarted
    (restart-policy containers may have started again)."""
    if read_daemon_json() != daemon_json or uo.recorded_offset(paths) is not None:
        back_to_prior(paths, daemon_json, s, daemon)
        return True
    if not daemon_answers():
        daemon.start()
        return True
    return False


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
