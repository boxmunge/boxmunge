# SPDX-License-Identifier: Apache-2.0
"""Backup encryption, decryption, and pruning.

Uses the `age` CLI for encryption with an identity file (age-keygen key pair).
All backup archives are encrypted before writing to disk.

The backup key at /opt/boxmunge/config/backup.key must be an age identity file
(contains AGE-SECRET-KEY-1...). On first run after upgrade from passphrase mode,
run `boxmunge doctor` to migrate the key.
"""

import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.paths import BoxPaths
from boxmunge.system_container import (
    SystemContainerError, SystemTools, connect, platform_owner,
)

_BACKUP_CMD_TIMEOUT = 600  # 10 minutes for large database dumps


class BackupError(Exception):
    """Raised when a backup operation fails."""


def resolve_backup_service(manifest: dict[str, Any]) -> str:
    """Resolve which compose service the backup dump/restore runs against.

    Resolution order:
      1. Explicit ``backup.service`` in the manifest.
      2. The sole service, when the manifest defines exactly one.

    Raises BackupError when neither applies — an ambiguous multi-service
    project must name its backup service explicitly. The old code defaulted
    to ``"web"``, which silently targeted a non-existent container for every
    project whose service wasn't named ``web`` (and let the pre-deploy
    snapshot fail to a swallowed warning).

    The backup service is a *compose* service and may legitimately be a
    backend (e.g. ``db``) that is absent from the manifest's ``services``
    block, so this does NOT cross-check it against ``services``.
    """
    backup_conf = manifest.get("backup", {}) or {}
    explicit = backup_conf.get("service")
    if explicit:
        return explicit
    services = manifest.get("services", {}) or {}
    if len(services) == 1:
        return next(iter(services))
    raise BackupError(
        f"backup.service is not set and the manifest defines {len(services)} "
        "services — set 'backup.service' to the compose service the "
        "dump/restore command runs in."
    )


@contextmanager
def _system_tools(paths: BoxPaths) -> Iterator[SystemTools]:
    """Yield a verified system-container handle; surface failures as BackupError.

    age runs only inside the system container. There is no host fallback:
    if the container is missing, stopped or mounted for another root, or a
    path is outside its mounts, the operation fails with the reason.
    """
    try:
        yield connect(paths)
    except SystemContainerError as e:
        raise BackupError(str(e)) from e


def chown_for_system_container(path: Path, paths: BoxPaths) -> None:
    """Give a fresh temp file or dir to the user the system container runs as.

    Backup dump/encrypt/restore temps are created with mkstemp/mkdtemp (owner
    only) as the invoking user: root for the container-update pre-backup, a
    root-run self-test or upgrade; deploy for the daily timer. age runs in
    the system container as the deploy user (the owner of the projects dir,
    checked by ``connect``), so a root-owned temp would be unreadable to it.
    Chown to that owner, not to the immediate directory's owner, which is
    root when root created the project tree. The mode is unchanged. A no-op
    when ownership already matches, the common deploy-invoked path.
    """
    uid, gid = platform_owner(paths)
    st = os.stat(path)
    if (st.st_uid, st.st_gid) != (uid, gid):
        os.chown(path, uid, gid)


def _read_recipient(tools: SystemTools) -> str:
    """Extract the public key (recipient) from the age identity file."""
    key_path = tools.paths.backup_key
    for line in key_path.read_text().splitlines():
        if line.startswith("# public key: "):
            return line.removeprefix("# public key: ").strip()
    # If no comment header, derive it via age-keygen
    result = tools.run(["age-keygen", "-y", tools.path(key_path)], timeout=_BACKUP_CMD_TIMEOUT)
    return result.stdout.strip()


def backup_filename(project_name: str) -> str:
    """Generate a timestamped backup filename."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
    return f"{project_name}-{ts}.tar.gz.age"


def encrypt_file(input_path: Path, output_path: Path, paths: BoxPaths) -> None:
    """Encrypt a file to the recipient of ``paths.backup_key`` using age.

    Writes to a temp file then renames to prevent partial encrypted files
    from appearing under the final name.
    """
    key_path = paths.backup_key
    if not key_path.exists():
        raise FileNotFoundError(f"Backup encryption key not found: {key_path}")

    with _system_tools(paths) as tools:
        fd, tmp_path_str = tempfile.mkstemp(
            dir=output_path.parent, prefix=".encrypt-", suffix=".tmp"
        )
        os.close(fd)
        tmp_path = Path(tmp_path_str)
        try:
            # age (in the system container) writes this temp via -o; align its
            # ownership so a root-invoked backup's temp stays writable to it.
            chown_for_system_container(tmp_path, paths)
            recipient = _read_recipient(tools)
            tools.run([
                "age", "--encrypt", "-r", recipient,
                "-o", tools.path(tmp_path),
                tools.path(input_path),
            ], timeout=_BACKUP_CMD_TIMEOUT)
            os.rename(tmp_path, output_path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise


def decrypt_file(input_path: Path, output_path: Path, paths: BoxPaths) -> None:
    """Decrypt an age-encrypted file with the identity at ``paths.backup_key``."""
    key_path = paths.backup_key
    if not key_path.exists():
        raise FileNotFoundError(f"Backup encryption key not found: {key_path}")

    with _system_tools(paths) as tools:
        tools.run([
            "age", "--decrypt", "-i", tools.path(key_path),
            "-o", tools.path(output_path),
            tools.path(input_path),
        ], timeout=_BACKUP_CMD_TIMEOUT)


@contextmanager
def decrypted_snapshot(snapshot_path: Path, paths: BoxPaths) -> Iterator[Path]:
    """Decrypt a snapshot into a private temp dir beside it; yield the plaintext.

    The temp dir lives in the project's backups directory (mounted into the
    system container, unlike /tmp) so age's -o path translates. It is 0700,
    chowned to the deploy user the container runs as so age can write into
    it, dot-prefixed so prune/sync globs ignore it, and always removed.
    """
    tmpdir = Path(tempfile.mkdtemp(dir=snapshot_path.parent, prefix=".restore-"))
    try:
        chown_for_system_container(tmpdir, paths)
        output = tmpdir / snapshot_path.stem  # strips .age
        decrypt_file(snapshot_path, output, paths)
        yield output
    finally:
        shutil.rmtree(tmpdir)


def prune_backups(
    backups_dir: Path, project_name: str, retention: int
) -> list[Path]:
    """Remove oldest backups beyond the retention count."""
    pattern = f"{project_name}-*.tar.gz.age"
    files = sorted(backups_dir.glob(pattern), key=lambda f: f.stat().st_mtime)

    to_prune = files[:-retention] if retention > 0 else files
    for f in to_prune:
        f.unlink()

    return to_prune
