"""sync_tree, durable_rename_dir and discard_dir (staging-own-tree, Crash safety)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from boxmunge import fileutil
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
