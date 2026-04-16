"""Tests for structured JSON-lines logging."""

import json
from pathlib import Path

from boxmunge.log import log_operation, log_warning, log_error, _reset_logger
from boxmunge.paths import BoxPaths


class TestStructuredLog:
    def setup_method(self):
        _reset_logger()

    def test_log_operation_writes_jsonlines(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.logs.mkdir(parents=True)
        log_operation("deploy", "Deploy completed", paths, project="myapp",
                      detail={"ref": "abc123"})
        lines = paths.log_file.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["level"] == "info"
        assert entry["component"] == "deploy"
        assert entry["project"] == "myapp"
        assert entry["msg"] == "Deploy completed"
        assert entry["detail"]["ref"] == "abc123"
        assert "ts" in entry

    def test_log_warning_sets_level(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.logs.mkdir(parents=True)
        log_warning("backup", "Key missing", paths)
        entry = json.loads(paths.log_file.read_text().strip())
        assert entry["level"] == "warn"
        assert entry["component"] == "backup"

    def test_log_error_sets_level(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.logs.mkdir(parents=True)
        log_error("health", "Container down", paths, project="myapp")
        entry = json.loads(paths.log_file.read_text().strip())
        assert entry["level"] == "error"
        assert entry["component"] == "health"
        assert entry["project"] == "myapp"

    def test_log_without_project(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.logs.mkdir(parents=True)
        log_operation("system", "Host check passed", paths)
        entry = json.loads(paths.log_file.read_text().strip())
        assert entry["project"] is None

    def test_multiple_entries_are_separate_lines(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.logs.mkdir(parents=True)
        log_operation("deploy", "First", paths, project="a")
        log_operation("deploy", "Second", paths, project="b")
        lines = paths.log_file.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["project"] == "a"
        assert json.loads(lines[1])["project"] == "b"
