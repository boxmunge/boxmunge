# SPDX-License-Identifier: Apache-2.0
"""Load, validate, and discover .boxmunge project config files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when .boxmunge config is missing, invalid, or malformed."""


_VALID_SERVER = re.compile(r'^[a-zA-Z0-9\.\-\:\[\]]+$')
_VALID_USER = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
_VALID_PROJECT = re.compile(r'^[a-z0-9][a-z0-9\-]{0,62}$')

_DEFAULTS = {
    "port": 922,
    "user": "deploy",
}


def load_config(path: Path) -> dict[str, Any]:
    """Load a .boxmunge config file. Returns validated config dict."""
    if not path.exists():
        raise ConfigError(f"Config not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ConfigError(f".boxmunge is not a YAML mapping: {path}")

    config: dict[str, Any] = {}
    config["server"] = raw.get("server")
    if not config["server"]:
        raise ConfigError("Required field 'server' is missing from .boxmunge.")

    config["port"] = raw.get("port", _DEFAULTS["port"])
    config["user"] = raw.get("user", _DEFAULTS["user"])
    config["project"] = raw.get("project", path.parent.name)

    validate_config(config)
    return config


def validate_config(config: dict[str, Any]) -> None:
    """Validate config values. Raises ConfigError on invalid input."""
    server = config.get("server", "")
    if not isinstance(server, str) or not _VALID_SERVER.match(server):
        raise ConfigError(
            f"Invalid 'server': {server!r}. "
            "Must be a hostname or IP address (no spaces, semicolons, "
            "backticks, pipes, or dollar signs)."
        )

    port = config.get("port")
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ConfigError(f"Invalid 'port': {port!r}. Must be an integer 1-65535.")

    user = config.get("user", "")
    if not isinstance(user, str) or not _VALID_USER.match(user):
        raise ConfigError(f"Invalid 'user': {user!r}. Must be a valid POSIX username.")

    project = config.get("project", "")
    if not isinstance(project, str) or not _VALID_PROJECT.match(project):
        raise ConfigError(
            f"Invalid 'project': {project!r}. Must be lowercase "
            "alphanumeric with hyphens, 1-63 chars."
        )


def discover_config(start: Path) -> Path:
    """Walk up from start looking for .boxmunge. Returns the path."""
    current = start.resolve()
    while True:
        candidate = current / ".boxmunge"
        if candidate.is_file():
            return candidate
        parent = current.parent
        if parent == current:
            raise ConfigError(
                "No .boxmunge found. Run 'boxmunge init' in your project root."
            )
        current = parent
