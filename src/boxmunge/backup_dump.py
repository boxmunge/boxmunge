# SPDX-License-Identifier: Apache-2.0
"""Run a project's backup dump command and own the plaintext it produces.

The dump runs inside the project's backup service via ``docker compose exec``
and streams to a 0600 ``.dump-*`` file in the project's backups dir, where it
stays as plaintext until it is encrypted. Every dump runs under the project
lock, so any ``.dump-*`` file found while holding that lock was stranded by a
process that died without unwinding (SIGKILL, power loss).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import boxmunge.backup as _backup
from boxmunge.backup import BACKUP_CMD_TIMEOUT, BackupError
from boxmunge.paths import BoxPaths
from boxmunge.service_exec import ServiceCommandTimeout, run_in_service

DUMP_PREFIX = ".dump-"


def execute_dump(
    paths: BoxPaths, project_name: str, dump_command: str, service: str,
) -> Path:
    """Run the dump command inside the project container and capture output.

    This function removes the plaintext on every failure; once it returns
    the path, removing it is the caller's job.
    """
    project_dir = paths.project_dir(project_name)
    backups_dir = paths.project_backups(project_name)
    if not backups_dir.exists():
        backups_dir.mkdir()
        # Created as root by a root-run backup, it would lock deploy out.
        _backup.chown_for_system_container(backups_dir, paths)
    fd, raw_path_str = tempfile.mkstemp(dir=backups_dir, prefix=DUMP_PREFIX, suffix=".tar.gz")
    raw_path = Path(raw_path_str)
    handed_off = False
    try:
        # Written and chowned through mkstemp's descriptor, never reopened by
        # name: the backups dir is deploy-writable, and a root-run backup
        # reopening a swapped-in symlink would overwrite its target.
        # The dump is later read by age in the system container (the deploy
        # uid); align ownership so a root-invoked backup's 0600 dump is
        # readable to it.
        with os.fdopen(fd, "wb") as outf:
            _backup.fchown_for_system_container(outf.fileno(), paths)
            try:
                result = run_in_service(
                    project_dir, project_name, service, dump_command,
                    timeout=BACKUP_CMD_TIMEOUT, stdout=outf, stderr=subprocess.PIPE,
                )
            except ServiceCommandTimeout as e:
                # The project lock is held for the whole dump; without a bound
                # a stuck database would also stall every later backup-all run.
                raise BackupError(
                    f"Dump command {e} (service {service!r}). Check that the "
                    "service is responsive and the dump_command finishes on its own."
                ) from e
            except OSError as e:
                raise BackupError(f"Dump command could not run: {e}") from e
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
                raise BackupError(f"Dump command failed: {stderr}")
            # The caller encrypts and removes the dump by name, so the name
            # must still be the file written here.
            written, named = os.fstat(outf.fileno()), os.lstat(raw_path)
            if (written.st_dev, written.st_ino) != (named.st_dev, named.st_ino):
                raise BackupError(f"{raw_path} was replaced while the dump ran; refusing to use it")
        handed_off = True
        return raw_path
    finally:
        if not handed_off:
            raw_path.unlink(missing_ok=True)


def remove_stale_dumps(paths: BoxPaths, project_name: str) -> list[Path]:
    """Delete plaintext dumps stranded by a dead process. Call under the project lock."""
    backups_dir = paths.project_backups(project_name)
    if not backups_dir.exists():
        return []
    stale = sorted(p for p in backups_dir.glob(f"{DUMP_PREFIX}*") if p.is_file())
    for p in stale:
        p.unlink()
    return stale
