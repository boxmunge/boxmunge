"""Atomic JSON state file read/write.

All writes use atomic_write_text (temp file + os.rename) to prevent
corruption from interrupted writes or concurrent access.
"""

import json
from pathlib import Path
from typing import Any

from boxmunge.fileutil import atomic_write_text


def write_state(path: Path, data: dict[str, Any]) -> None:
    """Write data as JSON to path, atomically."""
    content = json.dumps(data, indent=2, default=str) + "\n"
    atomic_write_text(path, content)


class StateError(Exception):
    """Raised when a state file exists but cannot be read or parsed."""


def read_state(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read a JSON state file. Returns default (empty dict) if file doesn't exist.

    Raises StateError, naming the file, if it exists but is unreadable,
    empty, corrupt, or not a JSON object. A missing file is a normal state
    (first run); a corrupt one is not, and must never pass for "no state".
    """
    if default is None:
        default = {}

    if not path.exists():
        return dict(default)

    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError) as e:  # ValueError covers JSONDecodeError
        raise StateError(f"Cannot read state file {path}: {e}") from e
    if not isinstance(data, dict):
        raise StateError(f"State file {path} is not a JSON object")
    return data
