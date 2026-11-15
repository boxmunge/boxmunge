"""install_commit_scripts runs as root over trees the deploy user owns: it
never follows a link on either side, never keeps setuid or setgid bits, and
keeps the destination's inode (commit_scripts)."""
from __future__ import annotations

import os
import stat

import pytest

from boxmunge import commit_scripts
from boxmunge.commit_scripts import install_commit_scripts
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.release import _refresh_dir_in_place


@pytest.fixture
def tree(tmp_path):
    tree = tmp_path / "project"
    (tree / "repo" / "boxmunge-scripts" / "lib").mkdir(parents=True)
    (tree / "repo" / "boxmunge-scripts" / "smoke.sh").write_text("echo ok\n")
    (tree / "repo" / "boxmunge-scripts" / "lib" / "common.txt").write_text("x\n")
    return tree


def test_the_commits_scripts_are_copied_executable(tree) -> None:
    install_commit_scripts(tree)
    smoke = tree / "boxmunge-scripts" / "smoke.sh"
    assert smoke.read_text() == "echo ok\n" and os.stat(smoke).st_mode & 0o111
    assert (tree / "boxmunge-scripts" / "lib" / "common.txt").read_text() == "x\n"


def test_setuid_and_setgid_bits_are_never_copied(tree) -> None:
    os.chmod(tree / "repo" / "boxmunge-scripts" / "smoke.sh", 0o6755)
    install_commit_scripts(tree)
    mode = os.stat(tree / "boxmunge-scripts" / "smoke.sh").st_mode
    assert not mode & (stat.S_ISUID | stat.S_ISGID) and mode & 0o755 == 0o755


def test_a_link_planted_in_the_destination_is_removed_not_written_through(
        tree, tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("precious\n")
    (tree / "boxmunge-scripts").mkdir()
    os.symlink(outside, tree / "boxmunge-scripts" / "smoke.sh")
    inode = os.stat(tree / "boxmunge-scripts").st_ino
    install_commit_scripts(tree)
    assert outside.read_text() == "precious\n"
    assert not os.path.islink(tree / "boxmunge-scripts" / "smoke.sh")
    assert (tree / "boxmunge-scripts" / "smoke.sh").read_text() == "echo ok\n"
    assert os.stat(tree / "boxmunge-scripts").st_ino == inode


def test_a_destination_that_is_a_link_is_replaced_not_followed(tree, tmp_path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, tree / "boxmunge-scripts")
    install_commit_scripts(tree)
    assert not os.path.islink(tree / "boxmunge-scripts")
    assert list(elsewhere.iterdir()) == []


def test_a_source_swapped_for_a_link_after_the_check_is_refused(
        tree, tmp_path, monkeypatch) -> None:
    secret = tmp_path / "root-only"
    secret.mkdir()
    (secret / "shadow").write_text("hash\n")
    real = commit_scripts.script_links

    def swap(scripts):
        found = real(scripts)
        os.rename(scripts, tmp_path / "moved")
        os.symlink(secret, scripts)
        return found
    monkeypatch.setattr(commit_scripts, "script_links", swap)
    with pytest.raises(OSError):
        install_commit_scripts(tree)
    assert not (tree / "boxmunge-scripts" / "shadow").exists()


def test_a_file_swapped_for_a_link_during_the_copy_is_refused(
        tree, tmp_path, monkeypatch) -> None:
    secret = tmp_path / "shadow"
    secret.write_text("hash\n")
    real = commit_scripts.copy_entry_nofollow

    def swap(src, name, dest):
        os.unlink(name, dir_fd=src)
        os.symlink(secret, name, dir_fd=src)
        real(src, name, dest)
    monkeypatch.setattr(commit_scripts, "copy_entry_nofollow", swap)
    with pytest.raises(ReleaseStateError, match="changed while it was copied"):
        install_commit_scripts(tree)
    assert not os.path.lexists(tree / "boxmunge-scripts" / "smoke.sh")


def test_a_hard_link_in_the_source_is_refused(tree, tmp_path) -> None:
    os.link(tree / "repo" / "boxmunge-scripts" / "smoke.sh", tmp_path / "other-name")
    with pytest.raises(ReleaseStateError, match="not a regular file"):
        install_commit_scripts(tree)


def test_a_bundle_refresh_never_writes_through_a_planted_link(tmp_path) -> None:
    """The bundle install shares the in-place refresh (release._install_entry)."""
    src, dest, outside = tmp_path / "src", tmp_path / "dest", tmp_path / "outside"
    src.mkdir()
    dest.mkdir()
    (src / "smoke.sh").write_text("new\n")
    os.chmod(src / "smoke.sh", 0o4755)
    outside.write_text("precious\n")
    os.symlink(outside, dest / "smoke.sh")
    _refresh_dir_in_place(src, dest)
    assert outside.read_text() == "precious\n"
    assert (dest / "smoke.sh").read_text() == "new\n"
    assert not os.stat(dest / "smoke.sh").st_mode & stat.S_ISUID
