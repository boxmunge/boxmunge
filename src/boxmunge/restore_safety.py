# SPDX-License-Identifier: Apache-2.0
"""Checks restore makes before it touches production (audit C-09).

``restore`` decrypts and verifies the chosen snapshot, and takes a safety
snapshot of the current data, while production is still running. Only then
does it stop anything. A snapshot that does not decrypt or unpack, or a
current state that cannot be saved first, leaves production untouched.
"""
from __future__ import annotations

import gzip
import tarfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

from boxmunge.backup import BackupError, encrypt_file
from boxmunge.commands.backup_cmd import _execute_dump
from boxmunge.paths import BoxPaths

_READ_CHUNK = 1 << 20


class RestoreError(Exception):
    """A restore step failed."""


def verify_plaintext(path: Path) -> None:
    """Raise RestoreError unless the decrypted snapshot looks restorable.

    It must be non-empty. A gzip stream must decompress to the end (catches
    truncation and corruption) and a tar archive must list. Other formats
    (a plain SQL dump, say) can only be checked for size; the project's
    restore_command is the final judge of their contents.
    """
    size = path.stat().st_size
    if size == 0:
        raise RestoreError("decrypted snapshot is empty")
    with open(path, "rb") as f:
        magic = f.read(2)
    try:
        if magic == b"\x1f\x8b":
            with gzip.open(path, "rb") as g:
                while g.read(_READ_CHUNK):
                    pass
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                t.getmembers()
    except (OSError, EOFError, zlib.error, tarfile.TarError) as e:
        raise RestoreError(f"decrypted snapshot does not unpack: {e}") from e


def safety_snapshot_name(project_name: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
    return f"{project_name}-pre-restore-{ts}.tar.gz.age"


def take_safety_snapshot(
    project_name: str, paths: BoxPaths, dump_command: str, service: str,
) -> Path:
    """Dump and encrypt the project's current data next to its backups.

    The file matches the usual snapshot pattern, so ``restore`` can list
    and restore it, and later nightly retention treats it like any other
    snapshot. It is never pruned here: pruning now could delete the very
    snapshot being restored.
    """
    if not dump_command:
        raise RestoreError(
            "cannot take a pre-restore safety snapshot: backup.dump_command "
            "is not set in the manifest (use --no-safety-snapshot to restore "
            "without one)"
        )
    project_dir = paths.project_dir(project_name)
    try:
        raw = _execute_dump(project_dir, dump_command, project_name, service)
    except BackupError as e:
        raise RestoreError(
            f"pre-restore safety snapshot failed: {e} (fix the service, or "
            f"use --no-safety-snapshot to restore without one)"
        ) from e
    out = paths.project_backups(project_name) / safety_snapshot_name(project_name)
    try:
        encrypt_file(raw, out, paths.backup_key)
    except (BackupError, FileNotFoundError) as e:
        raise RestoreError(f"pre-restore safety snapshot could not be encrypted: {e}") from e
    finally:
        raw.unlink(missing_ok=True)
    return out
