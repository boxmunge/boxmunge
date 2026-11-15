# SPDX-License-Identifier: Apache-2.0
"""Root's monthly rotation of the audit log (boxmunge-audit-rotate.timer).

An append-only file cannot be renamed or deleted, so rotation clears the
attribute on the active log, moves it to audit.jsonl.<YYYY-MM-DD>, sets the
attribute on that archive, opens (or adopts) a new active log and seals it,
then deletes archives past the newest AUDIT_ARCHIVES_KEPT, clearing each one's
attribute first. On a host recorded as unable to set the attribute
(api.audit_seal) the attribute steps are skipped. A failed step raises
SealError naming it; `_audit-rotate` alerts it with the fix.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.api.audit_seal import (
    SEAL_FIX, SealError, open_log, own_and_seal, read_unsupported, set_append_only,
)

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

AUDIT_ARCHIVES_KEPT = 12


@contextmanager
def _step(number: int, what: str) -> Iterator[None]:
    try:
        yield
    except (SealError, OSError) as e:
        raise SealError(f"audit log rotation step {number} ({what}) failed: {e}") from e


def _archives(logs: Path, active: str) -> list[str]:
    pattern = re.compile(rf"{re.escape(active)}\.\d{{4}}-\d{{2}}-\d{{2}}")
    return sorted((name for name in os.listdir(logs) if pattern.fullmatch(name)), reverse=True)


def rotate(paths: BoxPaths, today: date) -> str | None:
    """As root: move the active audit log to an archive named for *today*
    and start a new sealed one. Returns the archive's name, or None when the
    active log is empty (nothing is changed then). Raises SealError."""
    attribute = read_unsupported(paths) is None
    active = paths.audit_log
    archive = active.with_name(f"{active.name}.{today.isoformat()}")
    try:
        fd = open_log(active, create=False)
    except FileNotFoundError:
        raise SealError(f"{active} is missing, so there is nothing to rotate and every "
                        f"audited call is refused. Recreate it as root: {SEAL_FIX}") from None
    try:
        if os.fstat(fd).st_size == 0:
            return None
        if os.path.lexists(archive):
            raise SealError(f"audit log rotation step 2 (move to {archive.name}) refused: "
                            f"{archive} already exists. Nothing was changed")
        if attribute:
            with _step(1, "clear the attribute on the active log"):
                set_append_only(fd, False, where=active)
        with _step(2, f"move to {archive.name}"):
            os.rename(active, archive)
        if attribute:
            with _step(3, f"set the attribute on {archive.name}"):
                set_append_only(fd, True, where=archive)
    finally:
        os.close(fd)
    with _step(4, "open and seal the new active log"):
        new = open_log(active, create=True)   # adopts one a writer made meanwhile
        try:
            own_and_seal(new, active, attribute=attribute)
        finally:
            os.close(new)
    with _step(5, f"delete archives past the newest {AUDIT_ARCHIVES_KEPT}"):
        for name in _archives(paths.logs, active.name)[AUDIT_ARCHIVES_KEPT:]:
            _delete(paths.logs / name, attribute=attribute)
    return archive.name


def _delete(path: Path, *, attribute: bool) -> None:
    if attribute:
        fd = open_log(path, create=False)
        try:
            set_append_only(fd, False, where=path)
        finally:
            os.close(fd)
    os.unlink(path)
