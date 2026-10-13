"""Tests for boxmunge.state — atomic JSON state file management."""

import json
from pathlib import Path

import pytest

from boxmunge.state import StateError, read_state, write_state


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

    def test_corrupt_json_raises_state_error_naming_file(self, tmp_path: Path) -> None:
        """Audit C-15: a corrupt state file raises a typed error with its path."""
        state_file = tmp_path / "health.json"
        state_file.write_text('{"status": "ok"')
        with pytest.raises(StateError) as exc:
            read_state(state_file)
        assert str(state_file) in str(exc.value)

    def test_empty_file_raises_state_error(self, tmp_path: Path) -> None:
        state_file = tmp_path / "health.json"
        state_file.write_text("")
        with pytest.raises(StateError):
            read_state(state_file)

    def test_non_object_raises_state_error(self, tmp_path: Path) -> None:
        state_file = tmp_path / "health.json"
        state_file.write_text("[1, 2]")
        with pytest.raises(StateError, match="not a JSON object"):
            read_state(state_file)
