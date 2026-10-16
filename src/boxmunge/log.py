# SPDX-License-Identifier: Apache-2.0
"""Structured JSON-lines logging for boxmunge.

Logs to /opt/boxmunge/logs/boxmunge.log in JSON-lines format, rotated daily
(see boxmunge.log_rotation):
    {"ts": "...", "level": "info", "component": "deploy", "project": "myapp", "msg": "...", "detail": {...}}

Also logs to stderr for interactive use (human-readable format).
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from boxmunge.log_rotation import SharedLogFileHandler
from boxmunge.paths import BoxPaths

_logger: logging.Logger | None = None


class _JsonFormatter(logging.Formatter):
    """Format log records as JSON-lines."""

    def format(self, record: logging.LogRecord) -> str:
        # The record's creation time, not the time of formatting: rotation
        # files each entry by the day of this same instant.
        created = datetime.fromtimestamp(record.created, timezone.utc)
        entry: dict[str, Any] = {
            "ts": created.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
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


def get_logger(paths: BoxPaths) -> logging.Logger:
    """Get or create the boxmunge operational logger.

    `paths` is required: the logger always wants the log directory so its
    file handler can attach. Callers without paths must construct a
    BoxPaths(tmp_path) explicitly — the previous Optional-paths path
    silently dropped the file handler and made deploy logs vanish."""
    global _logger
    if _logger is not None:
        return _logger

    logger = logging.getLogger("boxmunge")
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    # On a cold build, drop only the stderr/file handlers this factory owns
    # (both are StreamHandler subclasses) rather than every handler. A test
    # that attaches its own non-StreamHandler capture handler before calling
    # get_logger (see _capture_log_records in the security-cmd tests) must not
    # have it silently stripped. NB: this does NOT protect a pytest caplog
    # handler — LogCaptureHandler IS a StreamHandler; caplog isolation instead
    # comes from the _reset_boxmunge_logger conftest fixture (restores
    # propagate=True and drops this module's cache between tests).
    for handler in list(logger.handlers):
        if isinstance(handler, logging.StreamHandler):
            logger.removeHandler(handler)

    # stderr handler (always, human-readable)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(_StderrFormatter())
    stderr_handler.setLevel(logging.INFO)
    logger.addHandler(stderr_handler)

    # JSON file handler with daily rotation, keep 90 days
    # (only if log dir exists; tests sometimes use a freshly-made BoxPaths
    # whose logs/ subdir hasn't been created yet — fine, just skip)
    if paths.logs.exists():
        fh = SharedLogFileHandler(paths.log_file)
        fh.setFormatter(_JsonFormatter())
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)

    _logger = logger
    return logger


def _log(
    level: int,
    component: str,
    message: str,
    paths: BoxPaths,
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
    paths: BoxPaths,
    project: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Log an operational event (deploy, backup, health change, etc.)."""
    _log(logging.INFO, component, message, paths, project, detail)


def log_warning(
    component: str,
    message: str,
    paths: BoxPaths,
    project: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Log a warning."""
    _log(logging.WARNING, component, message, paths, project, detail)


def log_error(
    component: str,
    message: str,
    paths: BoxPaths,
    project: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Log an error."""
    _log(logging.ERROR, component, message, paths, project, detail)
