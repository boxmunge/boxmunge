"""shift_tree on a real filesystem as root (the dind job)."""
from __future__ import annotations

import os
import resource
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from boxmunge.userns.shift import Direction, ShiftRefused, scan_tree, shift_tree
from tests.integration.userns.conftest import USERNS_DIND

pytestmark = USERNS_DIND
S = 1048576
F, I = Direction.FORWARD, Direction.INVERSE
# On the dind volume: the container's own overlayfs rootfs keeps no
# immutable or append-only flags.
BASE = Path("/var/lib/docker/boxmunge-shift-test")


@pytest.fixture
def tree(request):
    d = BASE / request.node.name
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    yield d
    subprocess.run(["chattr", "-R", "-i", "-a", str(d)], capture_output=True)
    shutil.rmtree(d, ignore_errors=True)


def _owners(root: Path) -> dict[str, tuple[int, int, int]]:
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in [*dirnames, *filenames, "."]:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            out[os.path.relpath(p, root)] = (st.st_uid, st.st_gid, st.st_mode)
    return out


def test_round_trip_keeps_the_container_view(tree) -> None:
    (tree / "pg").write_text("x"); os.chown(tree / "pg", 70, 70); os.chmod(tree / "pg", 0o600)
    (tree / "suid").write_text("x"); os.chown(tree / "suid", 999, 999); os.chmod(tree / "suid", 0o4755)
    (tree / "sgid").write_text("x"); os.chown(tree / "sgid", 999, 999); os.chmod(tree / "sgid", 0o2750)
    (tree / "sub").mkdir(); os.chown(tree / "sub", 999, 1000); os.chmod(tree / "sub", 0o2770)
    (tree / "sub" / "x").write_text("x"); os.link(tree / "sub" / "x", tree / "hard")
    os.symlink("/etc/passwd", tree / "lnk"); os.chown(tree / "lnk", 70, 70, follow_symlinks=False)
    os.mkfifo(tree / "fifo")
    socket.socket(socket.AF_UNIX).bind(str(tree / "sock"))
    before = _owners(tree)
    shift_tree(tree, S, F)
    after = _owners(tree)
    assert all(after[k][:2] == (before[k][0] + S, before[k][1] + S) for k in before)
    assert all(after[k][2] == before[k][2] for k in before)  # setuid/setgid restored
    assert os.stat("/etc/passwd").st_uid == 0  # the link target was not touched
    assert shift_tree(tree, S, F).changed == 0  # idempotent
    shift_tree(tree, S, I)
    assert _owners(tree) == before


def test_resume_after_a_crash_part_way(tree, monkeypatch) -> None:
    for i in range(50):
        (tree / f"f{i}").write_text("x"); os.chown(tree / f"f{i}", i, i)
    real, count = os.fchown, {"n": 0}

    def crash(fd, uid, gid):
        count["n"] += 1
        if count["n"] == 20:
            raise KeyboardInterrupt
        real(fd, uid, gid)
    monkeypatch.setattr(os, "fchown", crash)
    with pytest.raises(KeyboardInterrupt):
        shift_tree(tree, S, F)
    monkeypatch.setattr(os, "fchown", real)
    shift_tree(tree, S, F)
    assert all(os.lstat(tree / f"f{i}").st_uid == S + i for i in range(50))


def test_a_crash_between_chown_and_chmod_keeps_the_setuid_bit(tree, monkeypatch) -> None:
    """chown cleared the bit and the process died before restoring it; the
    first scan's list (journalled by the engine) restores it on resume."""
    (tree / "suid").write_text("x"); os.chown(tree / "suid", 999, 999); os.chmod(tree / "suid", 0o4755)
    setid = scan_tree(tree, S, F).setid
    assert setid == {"suid": 0o4755}

    def die(fd, mode):
        raise KeyboardInterrupt
    monkeypatch.setattr(os, "fchmod", die)
    with pytest.raises(KeyboardInterrupt):
        shift_tree(tree, S, F, setid)
    monkeypatch.undo()
    assert os.lstat(tree / "suid").st_mode & 0o7777 == 0o755  # the kernel cleared it
    assert scan_tree(tree, S, F).setid == {}  # a fresh scan no longer knows
    shift_tree(tree, S, F, setid)
    st = os.lstat(tree / "suid")
    assert (st.st_uid, st.st_mode & 0o7777) == (S + 999, 0o4755)


def test_every_refusal_changes_nothing(tree) -> None:
    (tree / "big").write_text("x"); os.chown(tree / "big", 70000, 70000)
    (tree / "acl").write_text("x"); subprocess.run(["setfacl", "-m", "u:1000:r", str(tree / "acl")], check=True)
    (tree / "cap").write_text("x"); subprocess.run(["setcap", "cap_net_raw+ep", str(tree / "cap")], check=True)
    (tree / "imm").write_text("x"); subprocess.run(["chattr", "+i", str(tree / "imm")], check=True)
    (tree / "app").write_text("x"); subprocess.run(["chattr", "+a", str(tree / "app")], check=True)
    os.mknod(tree / "dev", 0o600 | 0o020000, os.makedev(1, 3))
    (tree / "t").mkdir(); subprocess.run(["mount", "-t", "tmpfs", "tmpfs", str(tree / "t")], check=True)
    try:
        before = _owners(tree)
        with pytest.raises(ShiftRefused) as e:
            shift_tree(tree, S, F)
        text = " ".join(e.value.problems)
        for needle in ("uid 70000", "posix_acl_access", "security.capability", "imm: immutable",
                       "app: append-only", "dev: device node", "a mount point inside the tree"):
            assert needle in text
        assert _owners(tree) == before
    finally:
        subprocess.run(["umount", str(tree / "t")], check=True)


def test_many_sibling_dirs_do_not_exhaust_fds(tree) -> None:
    """Review Focus 1."""
    for i in range(2000):
        (tree / f"s{i}").mkdir()
    deep = tree
    for _ in range(300):
        deep = deep / "d"
    deep.mkdir(parents=True)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, max(hard, 4096)))
    try:
        assert shift_tree(tree, S, F).changed == 2301
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
    assert os.lstat(deep).st_uid == S


def test_odd_names_and_space_in_mount_point(tree) -> None:
    """Review Focus 2."""
    raw = os.fsencode(tree)
    for name in (b"with space", b"new\nline", b"bad\xffbyte"):
        with open(os.path.join(raw, name), "w") as f:
            f.write("x")
        os.chown(os.path.join(raw, name), 70, 70)
    shift_tree(tree, S, F)
    assert {os.lstat(os.path.join(raw, n)).st_uid for n in os.listdir(raw)} == {S + 70}
    (tree / "m p").mkdir()
    subprocess.run(["mount", "-t", "tmpfs", "tmpfs", str(tree / "m p")], check=True)
    try:
        assert any("m p: a mount point" in p for p in scan_tree(tree, S, I).problems)
    finally:
        subprocess.run(["umount", str(tree / "m p")], check=True)


def test_single_file_and_socket_roots(tree) -> None:
    (tree / "app.db").write_text("x"); os.chown(tree / "app.db", 1000, 1000)
    shift_tree(tree / "app.db", S, F)
    assert os.lstat(tree / "app.db").st_uid == S + 1000
    socket.socket(socket.AF_UNIX).bind(str(tree / "s"))
    shift_tree(tree / "s", S, F)
    assert os.lstat(tree / "s").st_uid == S


def test_a_link_planted_above_the_tree_shifts_nothing(tree) -> None:
    """What deploy or a container could plant above a bind source: the
    shift refuses it and /etc keeps its owners."""
    os.symlink("/", tree / "project")
    with pytest.raises(ShiftRefused, match="without following a link"):
        shift_tree(tree / "project" / "etc", S, F)
    assert os.stat("/etc").st_uid == 0 and os.stat("/etc/passwd").st_uid == 0
