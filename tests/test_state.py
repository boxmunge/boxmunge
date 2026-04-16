"""Tests for boxmunge.state — atomic JSON state file management."""

import json
import pytest
from pathlib import Path

from boxmunge.state import read_state, write_state


class TestWriteState:
    def test_writes_valid_json(self, tmp_path: Path) -> None:
        state_file = tmp_path / "test.json"
        data = {"status": "ok", "count": 42}
        write_state(state_file, data)
        assert state_file.exists()
        assert json.loads(state_file.read_text()) == data

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        state_file = tmp_path / "test.json"
        write_state(state_file, {"v": 1})
        write_state(state_file, {"v": 2})
        assert json.loads(state_file.read_text()) == {"v": 2}

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        state_file = tmp_path / "sub" / "dir" / "test.json"
        write_state(state_file, {"ok": True})
        assert state_file.exists()

    def test_atomic_write_no_partial_files(self, tmp_path: Path) -> None:
        """After write, no temp files should remain."""
        state_file = tmp_path / "test.json"
        write_state(state_file, {"data": "value"})
        files = list(tmp_path.iterdir())
        assert len(files) == 1
        assert files[0].name == "test.json"


class TestReadState:
    def test_reads_existing_state(self, tmp_path: Path) -> None:
        state_file = tmp_path / "test.json"
        state_file.write_text(json.dumps({"status": "ok"}))
        data = read_state(state_file)
        assert data == {"status": "ok"}

    def test_returns_default_for_missing_file(self, tmp_path: Path) -> None:
        state_file = tmp_path / "nope.json"
        data = read_state(state_file)
        assert data == {}

    def test_returns_custom_default(self, tmp_path: Path) -> None:
        state_file = tmp_path / "nope.json"
        data = read_state(state_file, default={"status": "unknown"})
        assert data == {"status": "unknown"}
