"""Tests for boxmunge.lock_holder — naming the process that holds a lock."""

import os
from pathlib import Path

from boxmunge.lock_holder import lock_holder


def _fake_proc(tmp_path: Path, lock: Path, pid: int = 4242,
               cmdline: bytes | None = b"boxmunge\0backup\0myapp\0") -> Path:
    st = lock.stat()
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "locks").write_text(
        "1: POSIX  ADVISORY  READ  99 08:01:1 0 EOF\n"
        f"2: FLOCK  ADVISORY  WRITE {pid} "
        f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino} 0 EOF\n"
    )
    if cmdline is not None:
        (proc / str(pid)).mkdir()
        (proc / str(pid) / "cmdline").write_bytes(cmdline)
    return proc


def test_holder_parses_proc_locks_by_inode(tmp_path: Path) -> None:
    lock = tmp_path / "myapp.lock"
    lock.write_text("")
    proc = _fake_proc(tmp_path, lock)
    assert lock_holder(lock, proc) == "pid 4242: boxmunge backup myapp"


def test_holder_without_readable_cmdline_is_pid_only(tmp_path: Path) -> None:
    lock = tmp_path / "myapp.lock"
    lock.write_text("")
    proc = _fake_proc(tmp_path, lock, cmdline=None)
    assert lock_holder(lock, proc) == "pid 4242"


def test_holder_cmdline_is_cut_at_200(tmp_path: Path) -> None:
    lock = tmp_path / "myapp.lock"
    lock.write_text("")
    proc = _fake_proc(tmp_path, lock, cmdline=b"x" * 500)
    assert lock_holder(lock, proc) == "pid 4242: " + "x" * 200


def test_no_holder_listed_is_none(tmp_path: Path) -> None:
    lock = tmp_path / "myapp.lock"
    lock.write_text("")
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "locks").write_text("1: FLOCK  ADVISORY  WRITE 7 08:01:999999999 0 EOF\n")
    assert lock_holder(lock, proc) is None


def _locks(tmp_path: Path, lock: Path, lines: list[str]) -> Path:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "locks").write_text("\n".join(lines) + "\n")
    return proc


def _id(lock: Path) -> str:
    st = lock.stat()
    return f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}"


def test_waiter_line_for_another_inode_is_skipped(tmp_path: Path) -> None:
    lock = tmp_path / "myapp.lock"
    lock.write_text("")
    proc = _locks(tmp_path, lock, [
        "1: -> FLOCK  ADVISORY  WRITE 55 08:01:999999999 0 EOF",
        f"2: FLOCK  ADVISORY  WRITE 4242 {_id(lock)} 0 EOF",
    ])
    assert lock_holder(lock, proc) == "pid 4242"


def test_waiter_on_our_inode_is_not_named_as_holder(tmp_path: Path) -> None:
    lock = tmp_path / "myapp.lock"
    lock.write_text("")
    proc = _locks(tmp_path, lock, [
        f"1: FLOCK  ADVISORY  WRITE 4242 {_id(lock)} 0 EOF",
        f"1: -> FLOCK  ADVISORY  WRITE 77 {_id(lock)} 0 EOF",
    ])
    assert lock_holder(lock, proc) == "pid 4242"


def test_holder_in_an_unseen_pid_namespace_is_none(tmp_path: Path) -> None:
    lock = tmp_path / "myapp.lock"
    lock.write_text("")
    proc = _locks(tmp_path, lock, [f"1: FLOCK  ADVISORY  WRITE 0 {_id(lock)} 0 EOF"])
    assert lock_holder(lock, proc) is None
