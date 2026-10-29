"""sync_tree, durable_rename_dir and discard_dir (staging-own-tree, Crash safety)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from boxmunge import fileutil, fs_nofollow
from boxmunge.fileutil import discard_dir, durable_rename_dir, sync_tree


def _tree(root: Path) -> Path:
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "f.txt").write_text("x")
    (root / "a" / "b" / "g.txt").write_text("y")
    os.symlink("f.txt", root / "a" / "link")
    return root / "a"


def test_sync_tree_fsyncs_every_file_and_directory(tmp_path, monkeypatch) -> None:
    tree = _tree(tmp_path)
    synced: list[int] = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(os.fstat(fd).st_ino), real(fd)))
    sync_tree(tree)
    want = {os.lstat(p).st_ino for p in (tree, tree / "b", tree / "f.txt", tree / "b" / "g.txt")}
    assert want <= set(synced)
    assert os.lstat(tree / "link").st_ino not in synced


def test_sync_tree_refuses_a_symlinked_root(tmp_path) -> None:
    tree = _tree(tmp_path)
    os.symlink(tree, tmp_path / "alias")
    with pytest.raises(OSError, match="symlink"):
        sync_tree(tmp_path / "alias")


@pytest.mark.skipif(os.getuid() == 0, reason="root reads mode-0 files")
def test_sync_tree_names_an_unreadable_file(tmp_path) -> None:
    tree = _tree(tmp_path)
    (tree / "f.txt").chmod(0)
    with pytest.raises(OSError, match="f.txt"):
        sync_tree(tree)


def test_durable_rename_dir_refuses_an_existing_destination(tmp_path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "dest").mkdir()
    with pytest.raises(FileExistsError):
        durable_rename_dir(tmp_path / "src", tmp_path / "dest")
    assert (tmp_path / "src").is_dir()


def test_durable_rename_dir_syncs_the_parent(tmp_path, monkeypatch) -> None:
    (tmp_path / "src").mkdir()
    synced: list[Path] = []
    monkeypatch.setattr(fileutil, "fsync_dir", synced.append)
    durable_rename_dir(tmp_path / "src", tmp_path / "dest")
    assert (tmp_path / "dest").is_dir() and synced == [tmp_path]


def test_discard_dir_removes_the_tree_and_leftover_debris(tmp_path) -> None:
    tree = _tree(tmp_path)
    (tmp_path / "a.discarded").mkdir()
    (tmp_path / "a.discarded" / "old").write_text("z")
    discard_dir(tree)
    assert not os.path.lexists(tree) and not os.path.lexists(tmp_path / "a.discarded")


def test_discard_dir_of_debris_removes_it_directly(tmp_path) -> None:
    (tmp_path / "x.discarded").mkdir()
    discard_dir(tmp_path / "x.discarded")
    assert list(tmp_path.iterdir()) == []


def test_discard_dir_missing_is_a_no_op(tmp_path) -> None:
    discard_dir(tmp_path / "absent")


def test_discard_dir_refuses_a_symlink(tmp_path) -> None:
    """Review Focus 5: a link planted where a slot was is never followed."""
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep").write_text("k")
    os.symlink(victim, tmp_path / "staged")
    with pytest.raises(OSError, match="not a directory"):
        discard_dir(tmp_path / "staged")
    assert (victim / "keep").read_text() == "k"


def test_crash_point_exits_only_when_named(monkeypatch) -> None:
    from boxmunge import crashpoint
    exited: list[int] = []
    monkeypatch.setattr(os, "_exit", exited.append)
    crashpoint.crash_point("txn.committed")
    monkeypatch.setenv(crashpoint.CRASH_ENV, "txn.committed")
    crashpoint.crash_point("txn.installed")
    crashpoint.crash_point("txn.committed")
    assert exited == [137]


class _Swap:
    """Root's chowns, recorded by inode instead of made, and a hook that
    lets a test swap a directory for a link at a chosen moment."""

    def __init__(self, monkeypatch) -> None:
        self.inodes: set[int] = set()
        real_stat, real_fstat = os.stat, os.fstat
        monkeypatch.setattr(fs_nofollow, "running_as_root", lambda: True)
        monkeypatch.setattr(fs_nofollow, "_deploy_owner", lambda: (os.getuid(), os.getgid()))

        def chown(path, uid, gid, *, dir_fd=None, follow_symlinks=True):
            st = real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
            self.inodes.add(st.st_ino)

        def fchown(fd, uid, gid):
            self.inodes.add(real_fstat(fd).st_ino)
        monkeypatch.setattr(fs_nofollow.os, "chown", chown)
        monkeypatch.setattr(fs_nofollow.os, "fchown", fchown)
        self.monkeypatch = monkeypatch

    def before_listing(self, directory: Path, swap) -> None:
        """Call swap() when the walk is about to list `directory`."""
        ino, real_scandir = os.lstat(directory).st_ino, os.scandir
        done = []

        def scandir(target="."):
            st = os.fstat(target) if isinstance(target, int) else os.lstat(target)
            if st.st_ino == ino and not done:
                done.append(True)
                swap()
            return real_scandir(target)
        self.monkeypatch.setattr(fs_nofollow.os, "scandir", scandir)


def _inodes(root: Path) -> set[int]:
    found = {os.lstat(root).st_ino}
    for dirpath, dirs, files in os.walk(root):
        found |= {os.lstat(os.path.join(dirpath, n)).st_ino for n in dirs + files}
    return found


def _outside(tmp_path: Path) -> Path:
    outside = tmp_path / "etc"
    (outside / "sub").mkdir(parents=True)
    (outside / "passwd").write_text("root")
    return outside


def _link_in(place: Path, target: Path, aside: Path) -> None:
    place.rename(aside)
    os.symlink(target, place)


def test_chown_tree_deploy_of_a_link_reowns_only_the_link(tmp_path, monkeypatch) -> None:
    """A planted top-level link (pdir/x -> /etc) must never hand its target
    to deploy."""
    outside = _outside(tmp_path)
    os.symlink(outside, tmp_path / "x")
    rec = _Swap(monkeypatch)
    fs_nofollow.chown_tree_deploy(tmp_path / "x")
    assert rec.inodes == {os.lstat(tmp_path / "x").st_ino}


def test_chown_tree_deploy_never_descends_a_nested_link(tmp_path, monkeypatch) -> None:
    outside = _outside(tmp_path)
    tree = tmp_path / "tree"
    (tree / "d").mkdir(parents=True)
    (tree / "f").write_text("f")
    os.symlink(outside, tree / "d" / "link")
    rec = _Swap(monkeypatch)
    fs_nofollow.chown_tree_deploy(tree)
    # The link itself is left alone too: owning it grants nothing.
    assert rec.inodes == _inodes(tree) - {os.lstat(tree / "d" / "link").st_ino}
    assert not rec.inodes & _inodes(outside)


def test_chown_tree_deploy_survives_the_top_swapped_for_a_link(tmp_path, monkeypatch) -> None:
    outside = _outside(tmp_path)
    tree = tmp_path / "tree"
    (tree / "f").mkdir(parents=True)
    rec = _Swap(monkeypatch)
    rec.before_listing(tree, lambda: _link_in(tree, outside, tmp_path / "aside"))
    fs_nofollow.chown_tree_deploy(tree)
    assert not rec.inodes & _inodes(outside)


def test_chown_tree_deploy_survives_a_subdirectory_swapped_for_a_link(tmp_path,
                                                                     monkeypatch) -> None:
    outside = _outside(tmp_path)
    tree = tmp_path / "tree"
    (tree / "sub" / "deeper").mkdir(parents=True)
    rec = _Swap(monkeypatch)
    rec.before_listing(tree / "sub",
                       lambda: _link_in(tree / "sub", outside, tmp_path / "aside"))
    fs_nofollow.chown_tree_deploy(tree)
    assert not rec.inodes & _inodes(outside)


def test_chown_tree_deploy_of_a_file_reowns_it(tmp_path, monkeypatch) -> None:
    (tmp_path / "f").write_text("x")
    rec = _Swap(monkeypatch)
    fs_nofollow.chown_tree_deploy(tmp_path / "f")
    assert rec.inodes == {os.lstat(tmp_path / "f").st_ino}


def test_chown_tree_deploy_is_silent_when_not_root(tmp_path, monkeypatch) -> None:
    (tmp_path / "d").mkdir()
    rec = _Swap(monkeypatch)
    monkeypatch.setattr(fs_nofollow, "running_as_root", lambda: False)
    fs_nofollow.chown_tree_deploy(tmp_path / "d")
    assert rec.inodes == set()


def test_chown_tree_deploy_leaves_links_and_non_regular_files_alone(tmp_path, monkeypatch, caplog) -> None:
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "f").write_text("x")
    os.symlink("f", tree / "link")
    os.mkfifo(tree / "pipe")
    rec = _Swap(monkeypatch)
    fs_nofollow.chown_tree_deploy(tree)
    assert os.lstat(tree / "f").st_ino in rec.inodes
    assert os.lstat(tree / "link").st_ino not in rec.inodes
    assert os.lstat(tree / "pipe").st_ino not in rec.inodes
    assert "not a regular file or directory" in caplog.text
