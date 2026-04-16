# SPDX-License-Identifier: Apache-2.0
"""Structured JSON-lines logging for boxmunge.

Logs to /opt/boxmunge/logs/boxmunge.log in JSON-lines format:
    {"ts": "...", "level": "info", "component": "deploy", "project": "myapp", "msg": "...", "detail": {...}}

Also logs to stderr for interactive use (human-readable format).
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from boxmunge.paths import BoxPaths

_logger: logging.Logger | None = None


class _JsonFormatter(logging.Formatter):
    """Format log records as JSON-lines."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname.lower().replace("warning", "warn"),
            "component": getattr(record, "component", ""),
            "project": getattr(record, "project", None),
            "msg": record.getMessage(),
        }
        detail = getattr(record, "detail", None)
        if detail is not None:
            entry["detail"] = detail
        return json.dumps(entry, default=str)


class _StderrFormatter(logging.Formatter):
    """Human-readable format for stderr."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        component = getattr(record, "component", "")
        project = getattr(record, "project", None)
        scope = component
        if project:
            scope = f"{component}:{project}"
        return f"{ts} {record.levelname} {scope} {record.getMessage()}"


def _reset_logger() -> None:
    """Reset the global logger. For testing only."""
    global _logger
    if _logger is not None:
        for h in _logger.handlers[:]:
            _logger.removeHandler(h)
            h.close()
    _logger = None


def get_logger(paths: BoxPaths | None = None) -> logging.Logger:
    """Get or create the boxmunge operational logger."""
    global _logger
    if _logger is not None:
        return _logger

    logger = logging.getLogger("boxmunge")
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    # Remove any pre-existing handlers (e.g. from other test runs)
    logger.handlers.clear()

    # stderr handler (always, human-readable)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(_StderrFormatter())
    stderr_handler.setLevel(logging.INFO)
    logger.addHandler(stderr_handler)

    # JSON file handler (if paths provided and log dir exists)
    if paths is not None and paths.logs.exists():
        fh = logging.FileHandler(paths.log_file)
        fh.setFormatter(_JsonFormatter())
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)

    _logger = logger
    return logger


def _log(
    level: int,
    component: str,
    message: str,
    paths: BoxPaths | None = None,
    project: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Internal: emit a structured log entry."""
    logger = get_logger(paths)
    logger.log(level, message, extra={
        "component": component,
        "project": project,
        "detail": detail,
    })


def log_operation(
    component: str,
    message: str,
    paths: BoxPaths | None = None,
    project: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Log an operational event (deploy, backup, health change, etc.)."""
    _log(logging.INFO, component, message, paths, project, detail)


def log_warning(
    component: str,
    message: str,
    paths: BoxPaths | None = None,
    project: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Log a warning."""
    _log(logging.WARNING, component, message, paths, project, detail)


def log_error(
    component: str,
    message: str,
    paths: BoxPaths | None = None,
    project: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Log an error."""
    _log(logging.ERROR, component, message, paths, project, detail)
