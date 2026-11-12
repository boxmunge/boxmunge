# SPDX-License-Identifier: Apache-2.0
"""Backup encryption, decryption, and pruning.

Uses the `age` CLI for encryption with an identity file (age-keygen key pair).
Every stored archive is encrypted. The dump it is made from is not: it sits
in the project's backups dir as a 0600 ``.dump-*`` file until encryption
finishes, and is removed whether or not encryption succeeds.

The backup key at /opt/boxmunge/config/backup.key must be an age identity file
(contains AGE-SECRET-KEY-1...). On first run after upgrade from passphrase mode,
run `boxmunge doctor` to migrate the key.
"""

import enum
import os
import re
import secrets
import shutil
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from boxmunge.fileutil import fsync_dir
from boxmunge.fs_nofollow import open_regular_nofollow
from boxmunge.paths import BoxPaths
from boxmunge.system_container import (
    SystemContainerError, SystemTools, connect, platform_owner,
)

BACKUP_CMD_TIMEOUT = 600  # 10 minutes for large database dumps


class BackupError(Exception):
    """Raised when a backup operation fails."""


class SnapshotUnconfirmed(BackupError):
    """The snapshot has its name, but that could not be confirmed on disk."""


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

    The temps sit in the deploy-writable backups dir, so a symlink swapped
    in after creation is re-owned itself, never followed.
    """
    uid, gid = platform_owner(paths)
    st = os.lstat(path)
    if (st.st_uid, st.st_gid) != (uid, gid):
        os.chown(path, uid, gid, follow_symlinks=False)


def fchown_for_system_container(fd: int, paths: BoxPaths) -> None:
    """chown_for_system_container on an open descriptor."""
    uid, gid = platform_owner(paths)
    st = os.fstat(fd)
    if (st.st_uid, st.st_gid) != (uid, gid):
        os.fchown(fd, uid, gid)


def _read_recipient(tools: SystemTools) -> str:
    """Extract the public key (recipient) from the age identity file."""
    key_path = tools.paths.backup_key
    for line in key_path.read_text().splitlines():
        if line.startswith("# public key: "):
            return line.removeprefix("# public key: ").strip()
    # If no comment header, derive it via age-keygen
    result = tools.run(["age-keygen", "-y", tools.path(key_path)], timeout=BACKUP_CMD_TIMEOUT)
    return result.stdout.strip()


class BackupKind(enum.Enum):
    """Why a snapshot was taken. Retention is counted separately per kind."""

    NIGHTLY = "nightly"        # backup-all (the 02:00 timer)
    PREDEPLOY = "predeploy"    # prod-deploy's snapshot before it changes anything
    PREUPDATE = "preupdate"    # container-update, before recreating changed images
    MANUAL = "manual"          # `backup <project>`, MCP, console, self-test
    PRERESTORE = "prerestore"  # restore's safety snapshot of the data it replaces
    PREMIGRATE = "premigrate"  # userns-migrate, before any downtime
    PRECHOWN = "prechown"      # data chown, before it stops the service
    PREPAUSE = "prepause"      # pause, before it stops the project


# Snapshots kept per project for each kind other than NIGHTLY, whose count is
# the manifest's backup.retention.
SNAPSHOT_RETENTION = {
    BackupKind.PREDEPLOY: 5,
    BackupKind.PREUPDATE: 3,
    BackupKind.MANUAL: 5,
    BackupKind.PRERESTORE: 3,
    BackupKind.PREMIGRATE: 2,
    BackupKind.PRECHOWN: 3,
    BackupKind.PREPAUSE: 3,
}

_TIMESTAMP = r"\d{4}-\d{2}-\d{2}T\d{6}"
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H%M%S"
_UNIQUE = r"[0-9a-f]{8}"
# A snapshot named for a time further ahead of the clock than this was
# taken while the clock ran ahead (or the clock has since stepped back).
AHEAD_SLACK = timedelta(minutes=10)


def utc_now() -> datetime:
    """The clock every snapshot is named by and judged against."""
    return datetime.now(timezone.utc)


def backup_filename(project_name: str, kind: BackupKind) -> str:
    """A new snapshot's name: ``<project>-<timestamp>-<unique>-<kind>.tar.gz.age``.

    The timestamp (to the second) orders snapshots and says when each was
    taken; it does not identify one. Two backups of a kind can finish in one
    second, and a clock that steps back revisits old seconds, so the random
    part is what keeps every snapshot's name its own.
    """
    ts = utc_now().strftime(_TIMESTAMP_FORMAT)
    return f"{project_name}-{ts}-{secrets.token_hex(4)}-{kind.value}.tar.gz.age"


def parse_snapshot(path: Path, project_name: str) -> tuple[str, BackupKind] | None:
    """(timestamp, kind) of a snapshot name, or None if it is not one.

    Snapshots on disk carry three name forms, and all stay restorable:
    backup_filename's; ``<project>-<ts>-<kind>``, written before names had
    a unique part; and ``<project>-<ts>``, written before kinds existed,
    which counts as nightly so it ages out as nightly backups arrive.
    """
    m = re.fullmatch(
        rf"{re.escape(project_name)}-({_TIMESTAMP})(?:-(?:{_UNIQUE}-)?([a-z]+))?"
        rf"\.tar\.gz\.age",
        path.name,
    )
    if not m:
        return None
    if m.group(2) is None:
        return m.group(1), BackupKind.NIGHTLY
    try:
        return m.group(1), BackupKind(m.group(2))
    except ValueError:
        return None


def snapshot_kind(path: Path, project_name: str) -> BackupKind | None:
    """The kind of a snapshot file, or None if the name is not a snapshot."""
    parsed = parse_snapshot(path, project_name)
    return parsed[1] if parsed else None


def dated_snapshots(backups_dir: Path, project_name: str,
                    ) -> list[tuple[datetime, BackupKind, Path]]:
    """The project's published snapshots with the time each is named for,
    oldest first: what is on disk, whatever any record says.

    backups/ is deploy-writable, so only a regular file counts (lstat: a
    link is never followed). A name whose timestamp is not a real time
    says nothing about when, and is left out. No directory: no snapshots.
    """
    try:
        entries = list(backups_dir.iterdir())
    except FileNotFoundError:
        return []
    found = []
    for entry in entries:
        parsed = parse_snapshot(entry, project_name)
        if parsed is None:
            continue
        try:
            at = datetime.strptime(parsed[0], _TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
            if not stat.S_ISREG(entry.lstat().st_mode):
                continue
        except (ValueError, FileNotFoundError):
            continue   # no such date; or removed meanwhile (prune)
        found.append((at, parsed[1], entry))
    return sorted(found, key=lambda snapshot: (snapshot[0], snapshot[2].name))


def dated_ahead(backups_dir: Path, project_name: str) -> list[Path]:
    """The project's snapshots named for a time ahead of the clock."""
    now = utc_now()
    return [path for at, _kind, path in dated_snapshots(backups_dir, project_name)
            if at - now > AHEAD_SLACK]


def publish_new(tmp_path: Path, path: Path) -> None:
    """Give a fully written temp file its final name, durably, replacing nothing.

    link(2) fails when the name is taken, where rename(2) would replace what
    holds it: a stored snapshot is never overwritten, whatever produced the
    name. The temp file must be in path's directory. Its data is synced
    before the link and the directory after it, as durable_rename does.
    Raises BackupError when path exists (a link at it included), or the
    filesystem refuses the link: the cause is named, and nothing is stored.
    Raises SnapshotUnconfirmed when the link was made and what follows it
    failed: the snapshot is there.
    """
    fd = open_regular_nofollow(tmp_path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(tmp_path, path, follow_symlinks=False)
    except FileExistsError as e:
        raise BackupError(
            f"{path} already exists; a stored snapshot is never overwritten. "
            f"Run the backup again: every snapshot gets a new name."
        ) from e
    except OSError as e:
        raise BackupError(
            f"Cannot give the snapshot its name {path}: {e}. Nothing was stored. "
            f"Fix the cause, then run the backup again."
        ) from e
    try:
        tmp_path.unlink()
        fsync_dir(path.parent)
    except OSError as e:
        raise SnapshotUnconfirmed(
            f"The snapshot {path.name} is in place, but it could not be confirmed "
            f"flushed to disk: {e}. A power loss now could lose it. Fix the cause, "
            f"then run the backup again."
        ) from e


def encrypt_file(input_path: Path, output_path: Path, paths: BoxPaths) -> None:
    """Encrypt a file to the recipient of ``paths.backup_key`` using age.

    Writes to a temp file, then publishes it under the final name
    (publish_new): no partial file appears there, and a file already there
    is never replaced (BackupError).
    """
    key_path = paths.backup_key
    if not key_path.exists():
        raise FileNotFoundError(f"Backup encryption key not found: {key_path}")

    with _system_tools(paths) as tools:
        fd, tmp_path_str = tempfile.mkstemp(
            dir=output_path.parent, prefix=".encrypt-", suffix=".tmp"
        )
        tmp_path = Path(tmp_path_str)
        try:
            # age (in the system container) writes this temp via -o; align its
            # ownership so a root-invoked backup's temp stays writable to it.
            try:
                fchown_for_system_container(fd, paths)
            finally:
                os.close(fd)
            recipient = _read_recipient(tools)
            tools.run([
                "age", "--encrypt", "-r", recipient,
                "-o", tools.path(tmp_path),
                tools.path(input_path),
            ], timeout=BACKUP_CMD_TIMEOUT)
            # age wrote the temp from another container; sync it before it
            # gets its name, or a power cut could leave an empty backup.
            publish_new(tmp_path, output_path)
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
        ], timeout=BACKUP_CMD_TIMEOUT)


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
    backups_dir: Path, project_name: str, kind: BackupKind, retention: int,
    *, keep: set[str] = frozenset(),
) -> list[Path]:
    """Remove the oldest snapshots of one kind beyond ``retention``, never
    one named in ``keep`` (a paired one: snapshot_pairings).

    Only files whose names parse as this project's snapshots of this kind are
    counted or removed; anything else in the directory is left alone.
    """
    if retention < 1:
        raise BackupError(
            f"Backup retention for {kind.value} snapshots must be at least 1, "
            f"got {retention}."
        )
    snapshots = sorted(
        (parsed[0], f) for f in backups_dir.iterdir()
        if (parsed := parse_snapshot(f, project_name)) and parsed[1] is kind
    )
    to_prune = [f for _, f in snapshots[:-retention] if f.name not in keep]
    for f in to_prune:
        f.unlink()
    return to_prune
