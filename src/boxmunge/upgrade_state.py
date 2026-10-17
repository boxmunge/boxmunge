# SPDX-License-Identifier: Apache-2.0
"""Upgrade state management — blocklist and probation.

Reads and writes JSON state files in /opt/boxmunge/upgrade-state/.
Used by the bash shim (via CLI wrappers) and Python commands.
"""
from __future__ import annotations

import fcntl
import json
import os
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, TYPE_CHECKING

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import open_regular_nofollow, read_text_nofollow

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


class UpgradeStateError(OSError):
    """A file in upgrade-state/ is not a plain regular file, or cannot be read."""

    @classmethod
    def of(cls, path: Path, e: OSError) -> UpgradeStateError:
        detail = e.strerror or str(e)
        return cls(detail if str(path) in detail else f"{path}: {detail}")


# What each state file holds, so an error can say how to repair it.
_REPAIR = {
    "blocklist.json": "it must be a JSON object mapping each version this box refuses "
                      "to install to why ({}: none). Repair it as root; deleting it "
                      "forgets every refused version",
    "probation.json": "it records an upgrade still on probation. Repair it as root, or "
                      "delete it to end probation",
}


def _read_json(path: Path) -> dict[str, Any]:
    """Read a JSON object file. Returns empty dict if missing.

    upgrade-state/ is deploy-writable and root reads it, so the file is
    opened without following a link and without blocking on a FIFO
    (read_text_nofollow). That, text that is not UTF-8 or not a JSON object
    is an UpgradeStateError naming the file: guessing at its contents could
    install a version this box refused, or skip a probation rollback.
    """
    import logging
    try:
        data = json.loads(read_text_nofollow(path))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        raise UpgradeStateError(
            f"{path} is not valid JSON ({e}); {_REPAIR[path.name]}") from e
    except UnicodeDecodeError as e:
        raise UpgradeStateError(
            f"{path} is not UTF-8 text ({e.reason}); inspect it and repair or remove it") from e
    except OSError as e:
        logging.getLogger("boxmunge").error("Cannot read %s: %s", path, e)
        raise UpgradeStateError.of(path, e) from e
    if not isinstance(data, dict):
        raise UpgradeStateError(f"{path} is not a JSON object; {_REPAIR[path.name]}")
    return data


def _write_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically. A link or FIFO deploy left at the name needs no
    refusal: rename(2) replaces the name itself, never opening or following
    what is there. (Deploy can still make a write fail, e.g. with a
    directory at the name, as it can remove any file here.)"""
    atomic_write_text(path, json.dumps(data, indent=2) + "\n")


# --- Blocklist ---

def is_blocklisted(paths: BoxPaths, version: str) -> bool:
    return version in _read_json(paths.blocklist)


def add_to_blocklist(paths: BoxPaths, version: str, reason: str) -> None:
    data = _read_json(paths.blocklist)
    data[version] = {
        "reason": reason,
        "failed_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(paths.blocklist, data)


def remove_from_blocklist(paths: BoxPaths, version: str) -> None:
    data = _read_json(paths.blocklist)
    data.pop(version, None)
    _write_json(paths.blocklist, data)


# --- Probation ---

def read_probation(paths: BoxPaths) -> dict[str, Any] | None:
    data = _read_json(paths.probation)
    return data if data else None


def write_probation(paths: BoxPaths, version: str, previous_slot: str, *, hours: int = 6) -> None:
    now = datetime.now(timezone.utc)
    _write_json(paths.probation, {
        "version": version,
        "started_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=hours)).isoformat(),
        "previous_slot": previous_slot,
    })


def clear_probation(paths: BoxPaths) -> None:
    paths.probation.unlink(missing_ok=True)


# --- Upgrade lock ---

class UpgradeInProgress(Exception):
    """upgrade.lock is held: the upgrade shim is running."""


@contextmanager
def upgrade_lock(paths: BoxPaths) -> Iterator[None]:
    """Hold the locks the upgrade shim takes, without waiting.

    Raises UpgradeInProgress if either is held. upgrade.lock is in root-only
    upgrade-root/, so deploy cannot replace it to let two upgrades run. The
    legacy lock in upgrade-state/ is what shims up to 0.10.1 and their venvs
    take, and one of them is still running while it upgrades a box to this
    release (acquire_lock in scripts/boxmunge-upgrade.d/state.sh says when
    it can go). Both are opened with open_regular_nofollow, so a planted
    link or FIFO is an UpgradeStateError naming it, instead of root opening
    some other file or blocking on the FIFO.
    """
    if paths.upgrade_root.is_symlink():
        raise UpgradeStateError(f"{paths.upgrade_root} is a symlink; refusing to use it "
                                "as root. Remove it and re-run.")
    for directory, mode in ((paths.upgrade_root, 0o700), (paths.upgrade_state, 0o777)):
        try:
            directory.mkdir(mode=mode, parents=True, exist_ok=True)
        except OSError as e:
            raise UpgradeStateError.of(directory, e) from e
    with ExitStack() as held:
        for lock in (paths.upgrade_lock, paths.legacy_upgrade_lock):
            held.enter_context(_flock(lock))
        yield


@contextmanager
def _flock(path: Path) -> Iterator[None]:
    try:
        fd = open_regular_nofollow(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    except OSError as e:
        raise UpgradeStateError.of(path, e) from e
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise UpgradeInProgress("an upgrade is in progress") from e
        yield
    finally:
        os.close(fd)
