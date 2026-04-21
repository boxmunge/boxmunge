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


def read_state(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read a JSON state file. Returns default (empty dict) if file doesn't exist."""
    if default is None:
        default = {}

    if not path.exists():
        return dict(default)

    with open(path) as f:
        return json.load(f)
