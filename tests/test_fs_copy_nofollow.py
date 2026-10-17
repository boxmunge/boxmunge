"""copy_entry_nofollow: root copies into a slot never through a link."""
from __future__ import annotations

import os

import pytest

from boxmunge.fs_nofollow import copy_entry_nofollow


@pytest.fixture
def dirs(tmp_path):
    src, dest = tmp_path / "src", tmp_path / "dest"
    src.mkdir()
    dest.mkdir()
    fds = os.open(src, os.O_RDONLY | os.O_DIRECTORY), os.open(dest, os.O_RDONLY | os.O_DIRECTORY)
    yield src, dest, *fds
    for fd in fds:
        os.close(fd)


def test_files_dirs_and_links_are_copied_as_they_are(dirs, tmp_path) -> None:
    src, dest, sfd, dfd = dirs
    (src / "tree" / "sub").mkdir(parents=True)
    (src / "tree" / "sub" / "run.sh").write_text("echo\n")
    (src / "tree" / "sub" / "run.sh").chmod(0o750)
    os.symlink(tmp_path, src / "tree" / "out")       # a link, kept as a link
    os.symlink(tmp_path, src / "dirlink")            # never followed
    for name in ("tree", "dirlink"):
        copy_entry_nofollow(sfd, name, dfd)
    assert (dest / "tree" / "sub" / "run.sh").read_text() == "echo\n"
    assert (dest / "tree" / "sub" / "run.sh").stat().st_mode & 0o777 == 0o750
    assert os.readlink(dest / "tree" / "out") == str(tmp_path)
    assert os.readlink(dest / "dirlink") == str(tmp_path)


def test_a_name_planted_at_the_destination_is_refused_not_written_through(dirs,
                                                                          tmp_path) -> None:
    src, dest, sfd, dfd = dirs
    (src / ".env").write_text("SECRET=1\n")
    victim = tmp_path / "victim"
    victim.write_text("untouched\n")
    os.symlink(victim, dest / ".env")
    with pytest.raises(FileExistsError):
        copy_entry_nofollow(sfd, ".env", dfd)
    assert victim.read_text() == "untouched\n"


def test_a_fifo_is_refused_without_blocking(dirs) -> None:
    src, _dest, sfd, dfd = dirs
    os.mkfifo(src / "pipe")
    with pytest.raises(OSError, match="not a file, directory or link"):
        copy_entry_nofollow(sfd, "pipe", dfd)
