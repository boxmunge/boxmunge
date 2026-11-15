# SPDX-License-Identifier: Apache-2.0
"""Root's monthly rotation of the audit log (boxmunge-audit-rotate.timer).

An append-only file cannot be renamed or deleted, so rotation clears the
attribute on the active log, moves it to audit.jsonl.<YYYY-MM-DD>, sets the
attribute on that archive, opens (or adopts) a new active log and seals it,
then deletes archives past the newest AUDIT_ARCHIVES_KEPT, clearing each one's
attribute first. On a host recorded as unable to set the attribute
(api.audit_seal) the attribute steps are skipped. From step 1 until the new
log is sealed, a marker in upgrade-root/ says a rotation is in progress, so a
health tick in that window warns instead of erroring (which would roll back
an upgrade in probation). A failed step raises SealError naming it and its
fix; `_audit-rotate` alerts both.
"""
from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.api.audit_seal import (
    SealError, archives, mark_rotating, open_log, own_and_seal, read_unsupported,
    set_append_only, unmark_rotating,
)

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

AUDIT_ARCHIVES_KEPT = 12
RERUN = "sudo systemctl start boxmunge-audit-rotate.service"


@contextmanager
def _step(number: int, what: str) -> Iterator[None]:
    try:
        yield
    except SealError as e:
        raise SealError(f"audit log rotation step {number} ({what}) failed: {e}", e.fix) from e
    except OSError as e:
        raise SealError(f"audit log rotation step {number} ({what}) failed: {e}") from e


def rotate(paths: BoxPaths, today: date) -> str | None:
    """As root: move the active audit log to an archive named for *today*
    and start a new sealed one. Returns the archive's name, or None when the
    active log is empty (nothing is changed then). Raises SealError, whose
    fix says what to do about that failure."""
    attribute = read_unsupported(paths) is None
    active = paths.audit_log
    archive = active.with_name(f"{active.name}.{today.isoformat()}")
    try:
        fd = open_log(active, create=False)
    except FileNotFoundError:
        raise SealError(f"{active} is missing, so there is nothing to rotate and every "
                        f"audited call is refused") from None
    try:
        if os.fstat(fd).st_size == 0:
            return None
        if os.path.lexists(archive):
            raise SealError(
                f"audit log rotation step 2 (move to {archive.name}) refused: {archive} "
                f"already exists. Nothing was changed",
                fix=f"move {archive} aside (sudo chattr -a {archive}; sudo mv {archive} "
                    f"{archive}.old), then run: {RERUN}")
        mark_rotating(paths)   # health warns, not errors, while the log is moved aside
        try:
            _move(fd, active, archive, attribute=attribute)
        except BaseException:
            unmark_rotating(paths)
            raise
    finally:
        os.close(fd)
    try:
        with _step(4, "open and seal the new active log"):
            new = open_log(active, create=True)   # adopts one a writer made meanwhile
            try:
                own_and_seal(new, active, attribute=attribute)
            finally:
                os.close(new)
    finally:
        unmark_rotating(paths)
    with _step(5, f"delete archives past the newest {AUDIT_ARCHIVES_KEPT}"):
        for name in archives(paths.logs, active.name)[AUDIT_ARCHIVES_KEPT:]:
            _delete(paths.logs / name, attribute=attribute)
    return archive.name


def _move(fd: int, active: Path, archive: Path, *, attribute: bool) -> None:
    """Steps 1 to 3: the active log, open as *fd*, becomes *archive*."""
    if attribute:
        with _step(1, "clear the attribute on the active log"):
            set_append_only(fd, False, where=active)
    with _step(2, f"move to {archive.name}"):
        os.rename(active, archive)
    if attribute:
        with _step(3, f"set the attribute on {archive.name}"):
            set_append_only(fd, True, where=archive)


def _delete(path: Path, *, attribute: bool) -> None:
    if attribute:
        try:
            fd = open_log(path, create=False)
        except SealError as e:
            raise SealError(str(e), fix=f"remove it (sudo rm {path}); the next rotation "
                                        f"deletes the old archives") from e
        try:
            set_append_only(fd, False, where=path)
        finally:
            os.close(fd)
    os.unlink(path)
