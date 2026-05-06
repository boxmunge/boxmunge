"""Tests for boxmunge.fileutil — atomic writes and project locking."""

import fcntl
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.fileutil import atomic_write_bytes, atomic_write_text
from boxmunge.fileutil import open_shared_lockfile, project_lock, LockError
from boxmunge.paths import BoxPaths


class TestOpenSharedLockfile:
    def test_creates_parent_dir(self, tmp_path: Path) -> None:
        lock = tmp_path / "deep" / "nested" / ".test.lock"
        fd = open_shared_lockfile(lock)
        try:
            assert lock.exists()
            assert lock.parent.is_dir()
        finally:
            os.close(fd)

    def test_file_mode_is_group_writable(self, tmp_path: Path) -> None:
        """Mode 0o664 so root and deploy group can both take the flock.

        Regression: when root creates the lock first (e.g. upgrade shim),
        deploy was getting EACCES on subsequent flock attempts.
        """
        lock = tmp_path / ".group-writable.lock"
        fd = open_shared_lockfile(lock)
        try:
            mode = lock.stat().st_mode & 0o777
            # Group write bit must be set; we accept 0o664 specifically
            # but tolerate umask narrowing if the caller's environment
            # is unusual. Hard requirement: group can write.
            assert mode & 0o060 == 0o060, f"mode {oct(mode)} is not group-writable"
        finally:
            os.close(fd)

    def test_existing_file_chmodded_back_to_0o664(self, tmp_path: Path) -> None:
        """If a file exists at narrower perms (e.g. created by older code),
        the helper must widen it on next open so locks remain shareable."""
        lock = tmp_path / ".old.lock"
        lock.touch(mode=0o600)
        fd = open_shared_lockfile(lock)
        try:
            mode = lock.stat().st_mode & 0o777
            assert mode == 0o664, f"mode should have been widened to 0o664, got {oct(mode)}"
        finally:
            os.close(fd)

    def test_returns_writable_fd(self, tmp_path: Path) -> None:
        lock = tmp_path / ".writable.lock"
        fd = open_shared_lockfile(lock)
        try:
            os.write(fd, b"x")  # would EBADF if read-only
            os.lseek(fd, 0, os.SEEK_SET)
            assert os.read(fd, 1) == b"x"
        finally:
            os.close(fd)


class TestAtomicWriteText:
    def test_writes_content(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        atomic_write_text(target, "hello world")
        assert target.read_text() == "hello world"

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        target.write_text("old content")
        atomic_write_text(target, "new content")
        assert target.read_text() == "new content"

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        target = tmp_path / "sub" / "dir" / "test.txt"
        atomic_write_text(target, "nested")
        assert target.read_text() == "nested"

    def test_no_temp_file_on_success(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        atomic_write_text(target, "content")
        temps = list(tmp_path.glob(".*tmp"))
        assert temps == []

    def test_no_partial_write_on_error(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        target.write_text("original")
        with patch("boxmunge.fileutil.os.fsync", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                atomic_write_text(target, "new content that should not appear")
        assert target.read_text() == "original"

    def test_temp_cleaned_up_on_error(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        with patch("boxmunge.fileutil.os.fsync", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                atomic_write_text(target, "content")
        temps = list(tmp_path.glob(".*tmp"))
        assert temps == []


class TestAtomicWriteBytes:
    def test_writes_content(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        atomic_write_bytes(target, b"hello world")
        assert target.read_bytes() == b"hello world"

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        target.write_bytes(b"old content")
        atomic_write_bytes(target, b"new content")
        assert target.read_bytes() == b"new content"

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        target = tmp_path / "sub" / "dir" / "test.bin"
        atomic_write_bytes(target, b"nested")
        assert target.read_bytes() == b"nested"

    def test_no_temp_file_on_success(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        atomic_write_bytes(target, b"content")
        temps = list(tmp_path.glob(".*tmp"))
        assert temps == []

    def test_no_partial_write_on_error(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        target.write_bytes(b"original")
        with patch("boxmunge.fileutil.os.fsync", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                atomic_write_bytes(target, b"new content that should not appear")
        assert target.read_bytes() == b"original"

    def test_temp_cleaned_up_on_error(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        with patch("boxmunge.fileutil.os.fsync", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                atomic_write_bytes(target, b"content")
        temps = list(tmp_path.glob(".*tmp"))
        assert temps == []

    def test_rename_failure_keeps_original(self, tmp_path: Path) -> None:
        """SIGKILL-equivalent: rename fails mid-write, original intact."""
        target = tmp_path / "test.bin"
        target.write_bytes(b"original")
        with patch("boxmunge.fileutil.os.rename", side_effect=OSError("simulated")):
            with pytest.raises(OSError):
                atomic_write_bytes(target, b"would-be-new")
        assert target.read_bytes() == b"original"
        temps = list(tmp_path.glob(".*tmp"))
        assert temps == []

    def test_mode_applied(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        atomic_write_bytes(target, b"content", mode=0o600)
        assert (target.stat().st_mode & 0o777) == 0o600


class TestProjectLock:
    def test_acquires_and_releases(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        paths.state.mkdir(parents=True, exist_ok=True)
        with project_lock("myapp", paths):
            lock_file = paths.project_lock_file("myapp")
            assert lock_file.exists()

    def test_blocks_concurrent_lock(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        paths.state.mkdir(parents=True, exist_ok=True)
        with project_lock("myapp", paths):
            with pytest.raises(LockError, match="Another operation"):
                with project_lock("myapp", paths):
                    pass

    def test_different_projects_independent(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        paths.state.mkdir(parents=True, exist_ok=True)
        with project_lock("app-a", paths):
            with project_lock("app-b", paths):
                pass  # should not raise

    def test_lock_file_persists_after_release(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        paths.state.mkdir(parents=True, exist_ok=True)
        with project_lock("myapp", paths):
            pass
        assert paths.project_lock_file("myapp").exists()

    def test_reacquire_after_release(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        paths.state.mkdir(parents=True, exist_ok=True)
        with project_lock("myapp", paths):
            pass
        with project_lock("myapp", paths):
            pass  # should not raise
