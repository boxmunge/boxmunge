"""Atomic JSON state file read/write.

All writes use a temp file + os.rename() to prevent corruption from
interrupted writes or concurrent access.
"""

import json
import os
import pwd
import tempfile
from pathlib import Path
from typing import Any


def _chown_deploy(path: str) -> None:
    """Best-effort chown to the deploy user.

    When boxmunge runs as root (e.g. via ``sudo``), files end up owned by
    root.  State files must be writable by the deploy user, so we fix
    ownership after every write.  Silently ignored when not running as root.
    """
    if os.getuid() != 0:
        return
    try:
        pw = pwd.getpwnam("deploy")
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except (KeyError, OSError):
        pass


def write_state(path: Path, data: dict[str, Any]) -> None:
    """Write data as JSON to path, atomically.

    Creates parent directories if they don't exist. Uses a temp file in the
    same directory followed by os.rename() which is atomic on Linux/macOS
    for same-filesystem operations.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.stem}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp_path, path)
        _chown_deploy(str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def read_state(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read a JSON state file. Returns default (empty dict) if file doesn't exist."""
    if default is None:
        default = {}

    if not path.exists():
        return dict(default)

    with open(path) as f:
        return json.load(f)
