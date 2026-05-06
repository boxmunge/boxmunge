# SPDX-License-Identifier: Apache-2.0
"""Structured JSON-lines logging for boxmunge.

Logs to /opt/boxmunge/logs/boxmunge.log in JSON-lines format:
    {"ts": "...", "level": "info", "component": "deploy", "project": "myapp", "msg": "...", "detail": {...}}

Also logs to stderr for interactive use (human-readable format).
"""

import grp
import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from typing import Any

from boxmunge.paths import BoxPaths

_logger: logging.Logger | None = None


class _SharedTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    """TimedRotatingFileHandler that ensures the log file is shared between root
    and the deploy group.

    boxmunge runs commands as both root (upgrade shim, systemd timers) and as
    the deploy user (restricted shell, project ops). Without explicit perms,
    whichever process opens the file first owns it, locking the other out
    after midnight rotation. We chgrp to 'deploy' and chmod 0o664 on every
    open so writers in either context can append.
    """

    def _open(self):  # type: ignore[override]
        # umask 0o002 → new file mode 0o664 if defaults applied
        old_umask = os.umask(0o002)
        try:
            stream = super()._open()
        finally:
            os.umask(old_umask)
        # Best-effort: align the file to deploy group + 0o664. Failures here
        # (caller is not file owner and not root) are silent because the file
        # is already open and writeable by the current process.
        try:
            deploy_gid = grp.getgrnam("deploy").gr_gid
            os.chown(self.baseFilename, -1, deploy_gid)
        except (KeyError, OSError):
            pass
        try:
            os.chmod(self.baseFilename, 0o664)
        except OSError:
            pass
        return stream


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
    # Remove any pre-existing handlers (e.g. from other test runs)
    logger.handlers.clear()

    # stderr handler (always, human-readable)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(_StderrFormatter())
    stderr_handler.setLevel(logging.INFO)
    logger.addHandler(stderr_handler)

    # JSON file handler with daily rotation, keep 90 days
    # (only if log dir exists; tests sometimes use a freshly-made BoxPaths
    # whose logs/ subdir hasn't been created yet — fine, just skip)
    if paths.logs.exists():
        fh = _SharedTimedRotatingFileHandler(
            paths.log_file,
            when="midnight",
            backupCount=90,
        )
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
