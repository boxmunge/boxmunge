# SPDX-License-Identifier: Apache-2.0
"""Make the latest stash restorable by boxmunge 0.10.1 (D18).

0.10.1's `stash restore` applies tarfile.data_filter, which rejects the
symlink members its own `stash create` wrote for git projects, so a
platform rollback would abort part-way. The upgrade's first step rewrites
the latest stash without them: every other member is copied in order with
its header and content (hardlinks pass the filter and restore the linked
content), the meta last; the copy is fully re-read and compared before it
replaces the original durably. Dropping the links loses nothing: a restore
only writes members, production's links stay on disk, and their targets
are the repository's. Any failure leaves the original and alerts.
"""
from __future__ import annotations

import hashlib
import json
import os
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.fileutil import durable_rename, open_regular_nofollow
from boxmunge.log import log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.stash import META_FILENAME, STASH_FORMAT_VERSION, list_stashes

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

REWRITE_PREFIX = ".rewrite-"


class StashRewriteError(Exception):
    """The stash cannot be rewritten safely."""


@dataclass(frozen=True)
class SanitizeResult:
    changed: bool
    dropped: list[str] = field(default_factory=list)
    error: str | None = None


def _record(tar: tarfile.TarFile, member: tarfile.TarInfo) -> tuple:
    """A member's header fields and content digest, for the read-back check."""
    f = tar.extractfile(member)
    digest = hashlib.sha256(f.read()).hexdigest() if f is not None else None
    return (member.name, member.type, member.mode, member.uid, member.gid, member.uname,
            member.gname, member.mtime, member.linkname, member.size, digest)


def _check_format(tar: tarfile.TarFile, members: list[tarfile.TarInfo]) -> None:
    if not members or members[-1].name != META_FILENAME:
        raise StashRewriteError("its meta is not the last member")
    meta_file = tar.extractfile(members[-1])
    if meta_file is None:
        raise StashRewriteError("its meta is not a regular file")
    got = json.loads(meta_file.read()).get("format_version")
    if got != STASH_FORMAT_VERSION:
        raise StashRewriteError(f"format {got!r} is not {STASH_FORMAT_VERSION}, "
                                f"the one this release can rewrite")


def _copy_members(tar: tarfile.TarFile, keep: list[tarfile.TarInfo], raw) -> None:
    # tarfile does not record an archive's format when reading; PAX holds
    # every header field, and _verify proves each one read back unchanged.
    with tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.PAX_FORMAT) as out:
        for member in keep:
            out.addfile(member, tar.extractfile(member) if member.isreg() else None)


def _write_copy(fd: int, owner: tuple[int, int], tar: tarfile.TarFile,
                keep: list[tarfile.TarInfo]) -> None:
    with os.fdopen(fd, "wb") as raw:
        os.fchown(raw.fileno(), *owner)
        os.fchmod(raw.fileno(), 0o600)
        _copy_members(tar, keep, raw)
        raw.flush()
        os.fsync(raw.fileno())


def _verify(copy: Path, want: list[tuple]) -> None:
    with os.fdopen(open_regular_nofollow(copy, os.O_RDONLY), "rb") as raw, \
            tarfile.open(fileobj=raw, mode="r:gz") as tar:
        got = [_record(tar, m) for m in tar.getmembers()]
    if got != want:
        raise StashRewriteError("the rewritten stash does not read back member for member")


def _rewrite(original: Path, tmp: Path) -> list[str]:
    """The dropped members' names; [] when there was nothing to drop.
    Removes its copy and raises on any failure."""
    created = False
    try:
        # stashes/ is deploy-writable: never read through a planted link.
        with os.fdopen(open_regular_nofollow(original, os.O_RDONLY), "rb") as raw, \
                tarfile.open(fileobj=raw, mode="r:gz") as tar:
            st = os.fstat(raw.fileno())
            members = tar.getmembers()
            _check_format(tar, members)
            dropped = [m.name for m in members if m.issym()]
            if not dropped:
                return []
            keep = [m for m in members if not m.issym()]
            want = [_record(tar, m) for m in keep]
            # O_EXCL | O_NOFOLLOW: a name planted at the temp path is refused, never used.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600)
            created = True
            _write_copy(fd, (st.st_uid, st.st_gid), tar, keep)
        _verify(tmp, want)
        durable_rename(tmp, original)
        return dropped
    except BaseException:
        if created:
            tmp.unlink(missing_ok=True)
        raise


def sanitize_latest_stash(paths: BoxPaths) -> SanitizeResult:
    """Rewrite the latest stash without symlink members. Never raises: a
    failure leaves the stash as it is and sends a priority-1 alert, and the
    upgrade continues."""
    stashes = list_stashes(paths)
    if not stashes:
        return SanitizeResult(False)
    original = stashes[0]
    tmp = paths.stashes / f"{REWRITE_PREFIX}{os.getpid()}.tmp"
    try:
        dropped = _rewrite(original, tmp)
    except Exception as e:  # noqa: BLE001 - never raises; the failure is alerted
        error = f"{type(e).__name__}: {e}"
        message = (f"The latest stash {original.name} could not be rewritten without its "
                   f"link members ({error}); it was left as it is, so a rollback's stash "
                   f"restore may abort on git links. If the platform rolls back to 0.10.1, "
                   f"check its stash restore finished, and extract any files it did not "
                   f"restore from {original} by hand, leaving out the link members.")
        log_warning("upgrade", message, paths)
        notify(paths, "upgrade: stash not rewritten", message, component="upgrade", priority=1)
        return SanitizeResult(False, error=error)
    for name in dropped:
        log_operation("upgrade", f"Dropped link member {name} from stash {original.name}", paths)
    return SanitizeResult(bool(dropped), dropped)
