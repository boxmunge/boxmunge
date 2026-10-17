# SPDX-License-Identifier: Apache-2.0
"""Checks restore makes before it touches production (audit C-09).

``restore`` decrypts and verifies the chosen snapshot, and takes a safety
snapshot of the current data, while production is still running. Only then
does it stop anything. A snapshot that does not decrypt or unpack, or a
current state that cannot be saved first, leaves production untouched.
"""
from __future__ import annotations

import gzip
import os
import tarfile
import zlib
from pathlib import Path

from boxmunge.fs_nofollow import open_regular_nofollow
from boxmunge.backup import BackupError, BackupKind, backup_filename, encrypt_file
from boxmunge.backup_dump import execute_dump
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
    # One no-follow descriptor for every read: the private temp dir is owned
    # by the deploy user (the system container's uid), so for a root-run
    # restore its contents could be swapped for a link to a root-only file.
    with os.fdopen(open_regular_nofollow(path, os.O_RDONLY), "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size == 0:
            raise RestoreError("decrypted snapshot is empty")
        magic = f.read(2)
        f.seek(0)
        try:
            if magic == b"\x1f\x8b":
                with gzip.GzipFile(fileobj=f, mode="rb") as g:
                    while g.read(_READ_CHUNK):
                        pass
            elif tarfile.is_tarfile(f):
                f.seek(0)
                with tarfile.open(fileobj=f) as t:
                    t.getmembers()
        except (OSError, EOFError, zlib.error, tarfile.TarError) as e:
            raise RestoreError(f"decrypted snapshot does not unpack: {e}") from e


def take_safety_snapshot(
    project_name: str, paths: BoxPaths, dump_command: str, service: str,
) -> Path:
    """Dump and encrypt the project's current data next to its backups.

    It is an ordinary snapshot of kind ``prerestore``, so ``restore`` can list
    and restore it. It is never pruned here, because pruning before the
    restore could delete the very snapshot being restored; ``restore`` prunes
    this kind after it succeeds.
    """
    if not dump_command:
        raise RestoreError(
            "cannot take a pre-restore safety snapshot: backup.dump_command "
            "is not set in the manifest (use --no-safety-snapshot to restore "
            "without one)"
        )
    try:
        raw = execute_dump(paths, project_name, dump_command, service)
    except BackupError as e:
        raise RestoreError(
            f"pre-restore safety snapshot failed: {e} (fix the service, or "
            f"use --no-safety-snapshot to restore without one)"
        ) from e
    try:
        out = paths.project_backups(project_name) / backup_filename(project_name, BackupKind.PRERESTORE)
        encrypt_file(raw, out, paths)
    except (BackupError, FileNotFoundError) as e:
        raise RestoreError(f"pre-restore safety snapshot could not be encrypted: {e}") from e
    finally:
        raw.unlink(missing_ok=True)
    return out
