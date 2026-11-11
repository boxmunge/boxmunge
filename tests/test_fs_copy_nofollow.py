"""copy_entry_nofollow: root copies into a slot never through a link."""
from __future__ import annotations

import errno
import os

import pytest

from boxmunge.fs_nofollow import copy_entry_nofollow
from boxmunge.git_slot import copy_project_entries


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


def test_setuid_and_setgid_bits_are_never_copied(dirs) -> None:
    src, dest, sfd, dfd = dirs
    (src / "tool").write_text("x")
    (src / "tool").chmod(0o4755)
    (src / "shared").mkdir()
    (src / "shared").chmod(0o3775)   # setgid and sticky
    for name in ("tool", "shared"):
        copy_entry_nofollow(sfd, name, dfd)
    assert (src / "tool").stat().st_mode & 0o7777 == 0o4755    # the source as it was
    assert (dest / "tool").stat().st_mode & 0o7777 == 0o755
    assert (dest / "shared").stat().st_mode & 0o7777 == 0o1775


# F09: os.write may write less than it was given. The real syscall is used
# throughout; only how much of each call reaches it is cut short.

PAYLOAD = b"0123456789abcdef" * 4


def _short_writes(monkeypatch, sizes: list[int | BaseException]) -> list[int]:
    """Each os.write in fs_nofollow takes the next of `sizes`: write at most
    that many bytes, or raise it. Past the list, writes are whole. Returns
    the byte counts asked for, as they happen."""
    asked: list[int] = []
    real = os.write
    plan = list(sizes)

    def write(fd: int, data) -> int:
        asked.append(len(data))
        step = plan.pop(0) if plan else len(data)
        if isinstance(step, BaseException):
            raise step
        return real(fd, bytes(data[:step])) if step else 0

    monkeypatch.setattr("boxmunge.fs_nofollow.os.write", write)
    return asked


def test_a_short_write_is_continued_until_the_file_is_whole(dirs, monkeypatch) -> None:
    src, dest, sfd, dfd = dirs
    (src / "asset").write_bytes(PAYLOAD)
    (src / "asset").chmod(0o640)
    asked = _short_writes(monkeypatch, [3, 1])
    copy_entry_nofollow(sfd, "asset", dfd)
    assert (dest / "asset").read_bytes() == PAYLOAD
    assert (dest / "asset").stat().st_mode & 0o777 == 0o640
    assert asked == [len(PAYLOAD), len(PAYLOAD) - 3, len(PAYLOAD) - 4]


def test_a_short_write_then_an_error_fails_the_copy(dirs, monkeypatch) -> None:
    """A full disk shows as a short write, then ENOSPC on the rest: the
    copy must raise, not return with a truncated file."""
    src, dest, sfd, dfd = dirs
    (src / "asset").write_bytes(PAYLOAD)
    _short_writes(monkeypatch, [3, OSError(errno.ENOSPC, "No space left on device")])
    with pytest.raises(OSError) as refused:
        copy_entry_nofollow(sfd, "asset", dfd)
    assert refused.value.errno == errno.ENOSPC


def _project_and_slot(tmp_path):
    project, release = tmp_path / "project", tmp_path / "slot"
    (project / "boxmunge-scripts").mkdir(parents=True)
    (project / "boxmunge-scripts" / "smoke.sh").write_bytes(PAYLOAD)
    release.mkdir()
    return project, release


def test_a_stage_gets_the_whole_script_after_a_short_write(tmp_path, monkeypatch) -> None:
    """What the copy is for: a git stage's auxiliary files (git_slot)."""
    project, release = _project_and_slot(tmp_path)
    _short_writes(monkeypatch, [3])
    copy_project_entries(project, release)
    assert (release / "boxmunge-scripts" / "smoke.sh").read_bytes() == PAYLOAD


def test_a_stage_fails_rather_than_carry_a_truncated_script(tmp_path, monkeypatch) -> None:
    project, release = _project_and_slot(tmp_path)
    _short_writes(monkeypatch, [3, OSError(errno.ENOSPC, "No space left on device")])
    with pytest.raises(OSError) as refused:
        copy_project_entries(project, release)
    assert refused.value.errno == errno.ENOSPC


def test_a_write_that_makes_no_progress_is_an_error(dirs, monkeypatch) -> None:
    src, _dest, sfd, dfd = dirs
    (src / "asset").write_bytes(PAYLOAD)
    _short_writes(monkeypatch, [3, 0])
    with pytest.raises(OSError, match="wrote nothing"):
        copy_entry_nofollow(sfd, "asset", dfd)
