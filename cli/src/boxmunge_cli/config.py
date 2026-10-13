# SPDX-License-Identifier: Apache-2.0
"""Load, validate, and discover .boxmunge project config files.

.boxmunge holds the connection details (server, port, user) and the project
name. Every value is checked with fullmatch, unknown keys are errors, and
every error names the file it came from.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when .boxmunge config is missing, invalid, or malformed."""


# A hostname or an IP address (IPv6 unbracketed; scp brackets it itself).
_VALID_SERVER = re.compile(r"[A-Za-z0-9:][A-Za-z0-9.:-]*")
_VALID_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_VALID_PROJECT = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")

_KEYS = ("server", "port", "user", "project")
_DEFAULTS = {
    "port": 922,
    "user": "deploy",
}


def load_config(path: Path) -> dict[str, Any]:
    """Load a .boxmunge config file. Returns validated config dict."""
    if not path.exists():
        raise ConfigError(f"Config not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"{path}: cannot be read as YAML: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: not a YAML mapping")

    unknown = sorted(str(k) for k in raw if k not in _KEYS)
    if unknown:
        raise ConfigError(f"{path}: unknown key(s) {', '.join(unknown)}; "
                          f"valid keys are {', '.join(_KEYS)}")
    if not raw.get("server"):
        raise ConfigError(f"{path}: required field 'server' is missing")

    config: dict[str, Any] = {
        "server": raw["server"],
        "port": raw.get("port", _DEFAULTS["port"]),
        "user": raw.get("user", _DEFAULTS["user"]),
        "project": raw.get("project", path.parent.name),
    }
    try:
        validate_config(config)
    except ConfigError as e:
        raise ConfigError(f"{path}: {e}") from e
    return config


def validate_config(config: dict[str, Any]) -> None:
    """Validate config values. Raises ConfigError on invalid input."""
    validate_connection(config)
    project = config.get("project", "")
    if not isinstance(project, str) or not _VALID_PROJECT.fullmatch(project):
        raise ConfigError(
            f"Invalid 'project': {project!r}. Must be lowercase "
            "alphanumeric with hyphens, 1-63 chars."
        )


def validate_connection(config: dict[str, Any]) -> None:
    """Validate server, port and user. Raises ConfigError on invalid input."""
    server = config.get("server", "")
    if not isinstance(server, str) or not _VALID_SERVER.fullmatch(server):
        raise ConfigError(
            f"Invalid 'server': {server!r}. Must be a hostname or IP address "
            "(letters, digits, '.', '-', ':'; IPv6 without brackets)."
        )

    port = config.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigError(f"Invalid 'port': {port!r}. Must be an integer 1-65535.")

    user = config.get("user", "")
    if not isinstance(user, str) or not _VALID_USER.fullmatch(user):
        raise ConfigError(f"Invalid 'user': {user!r}. Must be a valid POSIX username.")


def _is_repo_root(directory: Path) -> bool:
    return any((directory / vcs).exists() for vcs in (".git", ".hg", ".svn"))


def discover_config(start: Path) -> Path:
    """Find .boxmunge in start or a parent directory.

    The search stops at the repository root (a directory holding .git, .hg
    or .svn) and never reaches the home directory, so a stray ~/.boxmunge
    cannot capture every project under home.
    """
    home = Path(os.path.expanduser("~")).resolve()
    current = start.resolve()
    while current != home:
        candidate = current / ".boxmunge"
        if candidate.is_file():
            return candidate
        if _is_repo_root(current) or current.parent == current:
            break
        current = current.parent
    raise ConfigError(
        f"No .boxmunge found in {start.resolve()} or its parents (the search stops "
        "at the repository root and the home directory). Run 'boxmunge init' in "
        "your project root."
    )
