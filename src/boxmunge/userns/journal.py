# SPDX-License-Identifier: Apache-2.0
"""The migration journal: one root-only JSON file, rewritten after every step.

/opt/boxmunge/upgrade-root/ is root-only (0700); the journal is 0600, never
read through a symlink, and replaced by an atomic, durable rename (the new
file is synced before the rename and the directory after it), so after a
crash it holds the last step that completed, whole. It holds the direction
and phase, S, the original daemon.json, the prior store, the inventories,
a status per item (volume, bind source, image, project), the setuid list of
every shifted tree and the Caddyfile's original mode, so every step can be
resumed after a crash or reboot. init-host.sh writes the same format for a
fresh install, born committed (bootstrap/userns.sh).
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, field, fields
from typing import Any

from boxmunge.fileutil import atomic_write_bytes, fsync_dir
from boxmunge.paths import BoxPaths

VERSION = 1
FORWARD, ROLLBACK = "forward", "rollback"
FORWARD_PHASES = ("started", "prepared", "quiesced", "switched", "rebuilt", "applied",
                  "committed")
ROLLBACK_PHASES = ("rb-started", "rb-saved", "rb-quiesced", "rb-restored", "rb-switched",
                   "rb-rebuilt", "rolled-back")
_PHASES = {FORWARD: FORWARD_PHASES, ROLLBACK: ROLLBACK_PHASES}
RANGE = 65536


class JournalError(Exception):
    """The journal or its directory is not what root wrote."""


@dataclass
class Journal:
    direction: str
    phase: str
    offset: int
    daemon_json: str | None = None
    daemon_json_owner: list[int] | None = None  # [mode, uid, gid] of the original
    prior_store: dict[str, Any] = field(default_factory=dict)
    inventory: dict[str, Any] = field(default_factory=dict)
    rollback_inventory: dict[str, Any] = field(default_factory=dict)
    items: dict[str, str] = field(default_factory=dict)
    timers: dict[str, bool] = field(default_factory=dict)
    image_map: dict[str, str] = field(default_factory=dict)
    setid: dict[str, dict[str, int]] = field(default_factory=dict)
    caddyfile_mode: int | None = None
    applied_at: str | None = None
    failed: str | None = None
    fresh_install: bool = False

    def reached(self, phase: str) -> bool:
        order = _PHASES[self.direction]
        return order.index(self.phase) >= order.index(phase)


_TYPES: dict[str, tuple[type, ...]] = {
    "daemon_json": (str, type(None)), "daemon_json_owner": (list, type(None)), "prior_store": (dict,), "inventory": (dict,),
    "rollback_inventory": (dict,), "items": (dict,), "timers": (dict,), "image_map": (dict,),
    "setid": (dict,), "caddyfile_mode": (int, type(None)), "applied_at": (str, type(None)),
    "failed": (str, type(None)), "fresh_install": (bool,),
}


def _checked_dir(paths: BoxPaths, *, create: bool) -> bool:
    d = paths.upgrade_root
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        if not create:
            return False
        os.mkdir(d, 0o700)
        fsync_dir(d.parent)
        st = os.lstat(d)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) & 0o077):
        raise JournalError(f"{d} must be a directory owned by uid {os.geteuid()} with mode "
                           f"0700; it is not, so the journal there cannot be trusted")
    return True


def _validate(doc: Any) -> Journal:
    if (not isinstance(doc, dict) or doc.get("version") != VERSION
            or doc.get("direction") not in _PHASES
            or doc.get("phase") not in _PHASES.get(doc.get("direction"), ())
            or not isinstance(doc.get("offset"), int) or isinstance(doc.get("offset"), bool)
            or doc["offset"] <= 0 or doc["offset"] % RANGE):
        raise JournalError(f"the userns journal is malformed: {str(doc)[:200]}")
    known = {f.name for f in fields(Journal)}
    unknown = set(doc) - known - {"version"}
    if unknown:
        raise JournalError(f"the userns journal has unknown keys {sorted(unknown)}")
    wrong = sorted(k for k, types in _TYPES.items() if k in doc
                   and (not isinstance(doc[k], types)
                        or (bool not in types and isinstance(doc[k], bool))))
    if wrong:
        raise JournalError(f"the userns journal has values of the wrong type for {wrong}")
    return Journal(**{k: v for k, v in doc.items() if k != "version"})


def load_journal(paths: BoxPaths) -> Journal | None:
    if not _checked_dir(paths, create=False):
        return None
    try:
        fd = os.open(paths.userns_journal, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise JournalError(f"cannot open {paths.userns_journal}: {e}") from e
    with os.fdopen(fd, "rb") as f:
        try:
            return _validate(json.loads(f.read()))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise JournalError(f"{paths.userns_journal} is not JSON: {e}") from e


def save_journal(paths: BoxPaths, journal: Journal) -> None:
    _checked_dir(paths, create=True)
    doc = {"version": VERSION, **asdict(journal)}
    atomic_write_bytes(paths.userns_journal, (json.dumps(doc, indent=1) + "\n").encode(),
                       mode=0o600, owner=(os.geteuid(), os.getegid()))
