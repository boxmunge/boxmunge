"""Tests for structured JSON-lines logging."""

import json
import logging.handlers
from pathlib import Path

from boxmunge.log import (
    get_logger,
    log_operation,
    log_warning,
    log_error,
    _reset_logger,
)
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


class TestLogRotation:
    def setup_method(self):
        _reset_logger()

    def test_file_handler_is_timed_rotating(self, tmp_path: Path) -> None:
        """File handler must rotate daily; the plain FileHandler grew unbounded."""
        paths = BoxPaths(root=tmp_path / "bm")
        paths.logs.mkdir(parents=True)
        logger = get_logger(paths)
        file_handlers = [
            h for h in logger.handlers
            if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 1
        fh = file_handlers[0]
        assert isinstance(fh, logging.handlers.TimedRotatingFileHandler)

    def test_rotation_keeps_90_days(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.logs.mkdir(parents=True)
        logger = get_logger(paths)
        fh = next(
            h for h in logger.handlers
            if isinstance(h, logging.handlers.TimedRotatingFileHandler)
        )
        assert fh.backupCount == 90

    def test_rotation_at_midnight(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.logs.mkdir(parents=True)
        logger = get_logger(paths)
        fh = next(
            h for h in logger.handlers
            if isinstance(h, logging.handlers.TimedRotatingFileHandler)
        )
        # `when="midnight"` is normalised to "MIDNIGHT" internally.
        assert fh.when.upper() == "MIDNIGHT"

    def test_log_file_chmod_0o664_on_open(self, tmp_path: Path) -> None:
        """Regression: when the upgrade shim (root) opens the rotated log first,
        deploy user must still be able to append. The handler chmods 0o664 on
        every _open() so writers in either context can share the file."""
        paths = BoxPaths(root=tmp_path / "bm")
        paths.logs.mkdir(parents=True)
        logger = get_logger(paths)
        # Force a write to actually open the file
        logger.info("opener", extra={"component": "test", "project": None, "detail": None})
        log_file = paths.log_file
        assert log_file.exists()
        mode = log_file.stat().st_mode & 0o777
        # Must be group-writable; 0o664 is the target. We accept >=0o660 because
        # umask interactions on some systems may produce 0o660 if umask is 0o007.
        assert mode & 0o060 == 0o060, (
            f"log file {log_file} mode {oct(mode)} is not group-writable; "
            f"deploy user will be locked out after root-context rotation"
        )

    def test_handler_class_is_shared_subclass(self, tmp_path: Path) -> None:
        """The handler must be the boxmunge subclass that handles perms,
        not a plain TimedRotatingFileHandler."""
        from boxmunge.log import _SharedTimedRotatingFileHandler
        paths = BoxPaths(root=tmp_path / "bm")
        paths.logs.mkdir(parents=True)
        logger = get_logger(paths)
        fh = next(
            h for h in logger.handlers
            if isinstance(h, logging.handlers.TimedRotatingFileHandler)
        )
        assert isinstance(fh, _SharedTimedRotatingFileHandler)
