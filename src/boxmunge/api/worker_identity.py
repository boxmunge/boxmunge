# SPDX-License-Identifier: Apache-2.0
"""Who is running a job: boot id, pid and process start time.

A pid alone is reused after a worker dies, and means nothing after a reboot.
All three together say whether the process that claimed a job is still the
same one. /proc is a parameter so tests can fake it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxmunge.api.schema import INTEGER, STRING, obj
from boxmunge.state import StateError

PROC = Path("/proc")
# Fields of /proc/<pid>/stat after the last ")" start at field 3 (state);
# start time is field 22, so index 19 of that split.
_START_TIME_INDEX = 19

WORKER_SCHEMA = obj({"boot_id": STRING, "pid": INTEGER, "start_time": INTEGER})


@dataclass(frozen=True)
class WorkerIdentity:
    boot_id: str
    pid: int
    start_time: int

    def as_record(self) -> dict[str, Any]:
        return {"boot_id": self.boot_id, "pid": self.pid, "start_time": self.start_time}

    @classmethod
    def from_record(cls, d: dict[str, Any]) -> "WorkerIdentity":
        try:
            return cls(boot_id=d["boot_id"], pid=d["pid"], start_time=d["start_time"])
        except KeyError as e:
            raise StateError(
                f"Worker record is missing {e.args[0]!r}. The job record is corrupt."
            ) from e


def _boot_id(proc: Path) -> str:
    path = proc / "sys/kernel/random/boot_id"
    try:
        return path.read_text().strip()
    except OSError as e:
        raise StateError(
            f"Cannot read {path}: {e}. Job liveness cannot be decided without "
            f"the boot id; check that /proc is mounted."
        ) from e


def _start_time(proc: Path, pid: int) -> int | None:
    """Start time of pid, or None when the process does not exist."""
    path = proc / str(pid) / "stat"
    try:
        text = path.read_text()
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as e:
        raise StateError(f"Cannot read {path}: {e}.") from e
    fields = text[text.rindex(")") + 1:].split() if ")" in text else []
    if len(fields) <= _START_TIME_INDEX:
        raise StateError(f"Unparseable process stat in {path}: {text!r}.")
    try:
        return int(fields[_START_TIME_INDEX])
    except ValueError as e:
        raise StateError(f"Unparseable process stat in {path}: {text!r}.") from e


def current(proc: Path = PROC, pid: int | None = None) -> WorkerIdentity:
    """The identity of this process (or of pid, for tests)."""
    pid = os.getpid() if pid is None else pid
    start = _start_time(proc, pid)
    if start is None:
        raise StateError(f"Process {pid} has no entry under {proc}.")
    return WorkerIdentity(_boot_id(proc), pid, start)


def is_alive(identity: WorkerIdentity, proc: Path = PROC) -> bool:
    """True only if the boot, the pid and the start time all still match."""
    if _boot_id(proc) != identity.boot_id:
        return False
    return _start_time(proc, identity.pid) == identity.start_time
