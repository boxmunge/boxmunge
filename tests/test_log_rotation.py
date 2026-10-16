"""The operational log rotates correctly with several writer processes.

Writers are real, separate Python processes using get_logger, the way the
timers, the deploy shell and a long-lived MCP session share the file.
"""

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import boxmunge
from boxmunge import log_rotation
from boxmunge.health_checks.operational_log import check_operational_log
from boxmunge.log import _JsonFormatter
from boxmunge.log_rotation import SharedLogFileHandler, archive_path
from boxmunge.paths import BoxPaths

_WRITER = """
import sys
from pathlib import Path
from boxmunge.log import get_logger, log_operation
from boxmunge.paths import BoxPaths
paths = BoxPaths(Path(sys.argv[1]))
get_logger(paths)
print("ready", flush=True)
for line in sys.stdin:
    log_operation("test", line.strip(), paths)
    print("ok", flush=True)
"""

_BURST = """
import sys
from pathlib import Path
from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths
paths = BoxPaths(Path(sys.argv[1]))
for i in range(int(sys.argv[3])):
    log_operation("test", f"{sys.argv[2]}-{i}", paths)
"""


def _env() -> dict[str, str]:
    return {**os.environ, "PYTHONPATH": str(Path(boxmunge.__file__).parents[1])}


class _Writer:
    """A long-lived process holding the log open, writing on request."""

    def __init__(self, root: Path) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-c", _WRITER, str(root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, env=_env(),
        )
        assert self._reply() == "ready"

    def _reply(self) -> str:
        assert self.proc.stdout is not None
        return self.proc.stdout.readline().strip()

    def write(self, msg: str) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(msg + "\n")
        self.proc.stdin.flush()
        assert self._reply() == "ok"

    def close(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        assert self.proc.wait(timeout=30) == 0


def _msgs(path: Path) -> list[str]:
    return [json.loads(line)["msg"] for line in path.read_text().splitlines()]


def _yesterday() -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=1)


def _entry(msg: str, when: datetime) -> str:
    return json.dumps({"ts": when.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "msg": msg}) + "\n"


def _backdate_in_place(path: Path) -> datetime:
    """Make the file's first entry yesterday's, keeping its inode: a day has
    passed for whoever holds it open."""
    today = datetime.now(timezone.utc).date().isoformat()
    yesterday = _yesterday()
    data = path.read_bytes()
    assert data.startswith(b'{"ts": "' + today.encode())
    with open(path, "r+b") as f:
        f.write(data.replace(today.encode(), yesterday.date().isoformat().encode(), 1))
    return yesterday


@pytest.fixture
def paths(tmp_path: Path) -> BoxPaths:
    p = BoxPaths(tmp_path)
    p.logs.mkdir(parents=True)
    return p


def test_writers_opened_before_midnight_follow_the_rotation(paths: BoxPaths) -> None:
    """Both processes hold yesterday's file open; whichever writes first
    rotates it, and the other must not keep appending to the archive."""
    yesterday = _yesterday()
    paths.log_file.write_text(_entry("OLD", yesterday))
    first, second = _Writer(paths.root), _Writer(paths.root)
    try:
        first.write("A1")
        second.write("B1")
        second.write("B2")
        first.write("A2")
    finally:
        first.close()
        second.close()
    assert _msgs(archive_path(paths.log_file, yesterday.date())) == ["OLD"]
    assert _msgs(paths.log_file) == ["A1", "B1", "B2", "A2"]


def test_long_lived_writer_follows_a_rotation_by_another_process(paths: BoxPaths) -> None:
    resident = _Writer(paths.root)
    try:
        resident.write("before")
        yesterday = _backdate_in_place(paths.log_file)
        subprocess.run([sys.executable, "-c", _BURST, str(paths.root), "timer", "1"],
                       check=True, env=_env(), stderr=subprocess.DEVNULL)
        resident.write("after")
    finally:
        resident.close()
    assert _msgs(archive_path(paths.log_file, yesterday.date())) == ["before"]
    assert _msgs(paths.log_file) == ["timer-0", "after"]


def test_concurrent_writers_lose_and_tear_no_lines(paths: BoxPaths) -> None:
    procs = [
        subprocess.Popen([sys.executable, "-c", _BURST, str(paths.root), f"w{n}", "200"],
                         env=_env(), stderr=subprocess.DEVNULL)
        for n in range(4)
    ]
    for proc in procs:
        assert proc.wait(timeout=60) == 0
    msgs = _msgs(paths.log_file)  # json.loads fails on any torn line
    assert sorted(msgs) == sorted(f"w{n}-{i}" for n in range(4) for i in range(200))


def test_rotation_prunes_archives_beyond_ninety_days(paths: BoxPaths) -> None:
    today = datetime.now(timezone.utc).date()
    for age in range(2, 96):
        archive_path(paths.log_file, today - timedelta(days=age)).write_text("{}\n")
    paths.log_file.write_text(_entry("OLD", _yesterday()))
    subprocess.run([sys.executable, "-c", _BURST, str(paths.root), "new", "1"],
                   check=True, env=_env(), stderr=subprocess.DEVNULL)
    archives = sorted(p.name for p in paths.logs.glob("boxmunge.log.*"))
    assert len(archives) == 90
    assert archives[0] == archive_path(paths.log_file, today - timedelta(days=90)).name
    assert _msgs(archive_path(paths.log_file, today - timedelta(days=1))) == ["OLD"]


def test_rotation_merges_into_an_archive_an_older_version_already_wrote(paths: BoxPaths) -> None:
    yesterday = _yesterday()
    archive_path(paths.log_file, yesterday.date()).write_text(_entry("EARLY", yesterday))
    paths.log_file.write_text(_entry("LATE", yesterday))
    subprocess.run([sys.executable, "-c", _BURST, str(paths.root), "new", "1"],
                   check=True, env=_env(), stderr=subprocess.DEVNULL)
    assert _msgs(archive_path(paths.log_file, yesterday.date())) == ["EARLY", "LATE"]
    assert _msgs(paths.log_file) == ["new-0"]


def _record(msg: str, created: datetime) -> logging.LogRecord:
    record = logging.makeLogRecord({"msg": msg, "component": "test"})
    record.created = created.timestamp()
    return record


def test_entries_are_filed_by_their_own_timestamp(paths: BoxPaths) -> None:
    """An entry stamped just before midnight joins its own day's file even when
    written after midnight; the next day's first entry rotates it."""
    midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    late = midnight - timedelta(microseconds=1)
    paths.log_file.write_text(_entry("earlier", late - timedelta(hours=1)))
    handler = SharedLogFileHandler(paths.log_file)
    handler.setFormatter(_JsonFormatter())
    try:
        handler.emit(_record("late", late))
        assert _msgs(paths.log_file) == ["earlier", "late"]
        handler.emit(_record("next", midnight))
    finally:
        handler.close()
    assert _msgs(archive_path(paths.log_file, late.date())) == ["earlier", "late"]
    assert _msgs(paths.log_file) == ["next"]


def test_an_unrecognisable_active_file_is_reported_not_rotated(paths: BoxPaths, capsys) -> None:
    paths.log_file.write_text("not json\n")
    handler = SharedLogFileHandler(paths.log_file)
    try:
        handler.emit(_record("lost", datetime.now(timezone.utc)))
    finally:
        handler.close()
    assert "not a boxmunge log entry" in capsys.readouterr().err
    assert paths.log_file.read_text() == "not json\n"


_READ_ONLY_HOLDER = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
fcntl.flock(fd, fcntl.LOCK_EX)
print("held", flush=True)
sys.stdin.read()
"""


class _Holder:
    """Another process holding an flock through a read-only descriptor, as
    any local user can on anything they can open for reading."""

    def __init__(self, path: Path) -> None:
        self.proc = subprocess.Popen([sys.executable, "-c", _READ_ONLY_HOLDER, str(path)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        assert self.proc.stdout is not None
        assert self.proc.stdout.readline().strip() == "held"

    def release(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def test_locks_on_world_readable_paths_do_not_block_logging(paths: BoxPaths) -> None:
    paths.log_file.write_text(_entry("first", datetime.now(timezone.utc)))
    holders = [_Holder(paths.logs), _Holder(paths.log_file)]
    try:
        started = time.monotonic()
        subprocess.run([sys.executable, "-c", _BURST, str(paths.root), "w", "1"],
                       check=True, env=_env(), stderr=subprocess.DEVNULL, timeout=30)
        assert time.monotonic() - started < 5
    finally:
        for holder in holders:
            holder.release()
    assert _msgs(paths.log_file) == ["first", "w-0"]


def test_rotation_lock_is_not_readable_by_other_users(paths: BoxPaths) -> None:
    subprocess.run([sys.executable, "-c", _BURST, str(paths.root), "w", "1"],
                   check=True, env=_env(), stderr=subprocess.DEVNULL)
    lock = paths.logs / ".boxmunge.log.lock"
    assert lock.stat().st_mode & 0o777 == 0o660


def test_a_held_rotation_lock_loses_the_entry_loudly_instead_of_hanging(
        paths: BoxPaths, capsys) -> None:
    handler = SharedLogFileHandler(paths.log_file)
    handler.setFormatter(_JsonFormatter())
    os.close(log_rotation._open_lock(paths.logs / ".boxmunge.log.lock"))
    holder = _Holder(paths.logs / ".boxmunge.log.lock")
    try:
        with patch.object(log_rotation, "_LOCK_WAIT_SECONDS", 0.5):
            started = time.monotonic()
            handler.emit(_record("lost", datetime.now(timezone.utc)))
            assert time.monotonic() - started < 5
    finally:
        holder.release()
        handler.close()
    err = capsys.readouterr().err
    assert ".boxmunge.log.lock has been held" in err and "fuser" in err
    assert not paths.log_file.exists()


@pytest.mark.parametrize("first_line", ["\n", "   \n", "not json\n"])
def test_a_first_line_that_is_not_an_entry_is_reported(paths: BoxPaths, first_line: str) -> None:
    paths.log_file.write_text(first_line + _entry("later", _yesterday()))
    check = check_operational_log(paths)
    assert check.status == "warn"
    assert "not a boxmunge log entry" in check.detail and "Move the file aside" in check.detail


def test_operational_log_check_passes_for_empty_and_normal_logs(paths: BoxPaths) -> None:
    assert check_operational_log(paths).status == "ok"
    paths.log_file.write_text("")
    assert check_operational_log(paths).status == "ok"
    paths.log_file.write_text(_entry("x", datetime.now(timezone.utc)))
    assert check_operational_log(paths).status == "ok"


@pytest.mark.parametrize("planted", ["active", "archive"])
def test_a_planted_symlink_is_refused_loudly(paths: BoxPaths, capsys, planted: str) -> None:
    victim = paths.root / "victim"
    victim.write_text("keep\n")
    if planted == "active":
        paths.log_file.symlink_to(victim)
    else:
        yesterday = _yesterday()
        paths.log_file.write_text(_entry("old", yesterday))
        archive_path(paths.log_file, yesterday.date()).symlink_to(victim)
    handler = SharedLogFileHandler(paths.log_file)
    handler.setFormatter(_JsonFormatter())
    try:
        handler.emit(_record("new", datetime.now(timezone.utc)))
    finally:
        handler.close()
    assert victim.read_text() == "keep\n"
    err = capsys.readouterr().err
    assert "not a plain regular file" in err or "Too many levels of symbolic links" in err
