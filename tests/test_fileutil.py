"""Tests for boxmunge.fileutil — atomic writes and project locking."""

import fcntl
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.fileutil import atomic_write_text
from boxmunge.fileutil import project_lock, LockError
from boxmunge.paths import BoxPaths


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
