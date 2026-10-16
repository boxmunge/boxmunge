# SPDX-License-Identifier: Apache-2.0
"""The box's user-namespace remap: identity, offset record and cross-check.

Container uid N (0 <= N < 65536) is host uid S + N, where S starts
boxmunge-remap's single subordinate id range. Root records S in boxmunge.yml
(``userns: {name, offset}``) when it remaps the daemon. `remap_offset`
checks that record against every other source (the root-owned subid files,
daemon.json and the running daemon) on every call, so an edited record, a
hand-edited daemon.json or a daemon that came back on another store fails
loudly instead of being trusted. A box never remapped (no record, no
daemon.json setting, daemon not remapped) has offset 0, which makes every
shift and ownership rule a no-op.
"""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from boxmunge.docker_run import DockerError, run as _run
from boxmunge.fileutil import atomic_write_bytes
from boxmunge.paths import BoxPaths

REMAP_NAME = "boxmunge-remap"
DAEMON_REMAP_VALUE = f"{REMAP_NAME}:{REMAP_NAME}"
RANGE = 65536
_INFO_TIMEOUT = 10  # seconds; as health's other daemon probes
_FLOOR = 1_000_000
_MAX_ID = 2**32 - 1
ETC = Path("/etc")  # tests point this at a temporary directory
# Ids are ASCII digits only: str.isdigit() also accepts "²", which int() refuses.
_ID = re.compile(r"[0-9]+")


class RemapError(Exception):
    """The remap sources disagree, or one cannot be read."""


@dataclass(frozen=True)
class SubRange:
    owner: str
    start: int
    count: int

    def overlaps(self, start: int, count: int) -> bool:
        return self.start < start + count and start < self.start + self.count


def read_subids(path: Path) -> list[SubRange]:
    """The entries of a subuid/subgid file; [] when it does not exist."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError) as e:
        raise RemapError(f"cannot read {path}: {e}") from e
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) != 3 or not _ID.fullmatch(parts[1]) or not _ID.fullmatch(parts[2]):
            raise RemapError(f"{path}:{n} is not 'name:start:count': {line!r}")
        out.append(SubRange(parts[0], int(parts[1]), int(parts[2])))
    return out


def _remap_uid(etc: Path) -> str | None:
    """boxmunge-remap's uid from the passwd file, or None when it has none."""
    path = etc / "passwd"
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as e:
        raise RemapError(f"cannot read {path}: {e}") from e
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[0] == REMAP_NAME and _ID.fullmatch(parts[2]):
            return parts[2]
    return None


def remap_ranges(etc: Path) -> tuple[list[SubRange], list[SubRange]]:
    """boxmunge-remap's ranges in subuid and in subgid, in file order.

    Like Docker (idtools' lookupSubRangesFile, for both files), an entry is
    the user's when it names the user or the user's numeric uid.
    """
    owners = {REMAP_NAME} | ({uid} if (uid := _remap_uid(etc)) else set())
    return ([r for r in read_subids(etc / "subuid") if r.owner in owners],
            [r for r in read_subids(etc / "subgid") if r.owner in owners])


def allocate_offset(etc: Path, host_ids: set[int]) -> int:
    """S for boxmunge-remap: its own range when it has exactly one aligned
    range of 65536 at the same start in both files; otherwise the first
    65536-aligned block >= 1,000,000 that is free in both files and holds no
    host uid or gid."""
    uids, gids = remap_ranges(etc)
    if uids or gids:
        if (len(uids) == len(gids) == 1 and uids[0].start == gids[0].start
                and uids[0].count == gids[0].count == RANGE and uids[0].start % RANGE == 0):
            return uids[0].start
        raise RemapError(
            f"{REMAP_NAME} already has subordinate ids other than one aligned range "
            f"of {RANGE} at the same start in both files ({uids} / {gids}). Fix "
            f"{etc / 'subuid'} and {etc / 'subgid'} by hand, then run the migration again.")
    taken = read_subids(etc / "subuid") + read_subids(etc / "subgid")
    start = -(-_FLOOR // RANGE) * RANGE
    while start + RANGE - 1 <= _MAX_ID:
        if not any(r.overlaps(start, RANGE) for r in taken) \
                and not any(start <= i < start + RANGE for i in host_ids):
            return start
        start += RANGE
    raise RemapError(f"no free block of {RANGE} ids above {_FLOOR} in subuid and subgid")


def _record_block(offset: int) -> str:
    return f"userns:\n  name: {REMAP_NAME}\n  offset: {offset}\n"


def recorded_offset(paths: BoxPaths) -> int | None:
    """S from boxmunge.yml, or None when it has no userns record."""
    try:
        doc = yaml.safe_load(paths.config_file.read_text()) or {}
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise RemapError(f"cannot read {paths.config_file}: {e}") from e
    block = doc.get("userns") if isinstance(doc, dict) else None
    if block is None:
        return None
    value = block.get("offset") if isinstance(block, dict) else None
    if (not isinstance(block, dict) or block.get("name") != REMAP_NAME
            or not isinstance(value, int) or isinstance(value, bool)
            or value <= 0 or value % RANGE):
        raise RemapError(
            f"{paths.config_file}: userns must be {{name: {REMAP_NAME}, offset: <a positive "
            f"multiple of {RANGE}>}}, got {block!r}")
    return value


def _rewrite_config(paths: BoxPaths, text: str) -> None:
    st = os.lstat(paths.config_file)
    atomic_write_bytes(paths.config_file, text.encode(), mode=stat.S_IMODE(st.st_mode),
                       owner=(st.st_uid, st.st_gid))


def write_offset_record(paths: BoxPaths, offset: int) -> None:
    """Append the userns record (root only; idempotent)."""
    current = recorded_offset(paths)
    if current == offset:
        return
    if current is not None:
        raise RemapError(f"{paths.config_file} already records offset {current}, not {offset}")
    text = paths.config_file.read_text()
    _rewrite_config(paths, text.rstrip("\n") + "\n" + _record_block(offset))


def remove_offset_record(paths: BoxPaths, offset: int) -> None:
    """Remove exactly the block write_offset_record appended (rollback)."""
    if recorded_offset(paths) is None:
        return
    text = paths.config_file.read_text()
    block = _record_block(offset)
    if text.count(block) != 1:
        raise RemapError(f"{paths.config_file}: the userns record was edited by hand; "
                         f"remove the 'userns:' block yourself")
    _rewrite_config(paths, text.replace(block, "").rstrip("\n") + "\n")


def docker_info() -> dict[str, Any]:
    """`docker info` as a mapping. Raises RemapError when the daemon cannot say."""
    try:
        out = _run(["docker", "info", "--format", "{{json .}}"], capture=True,
                   timeout=_INFO_TIMEOUT).stdout
        doc = json.loads(out)
    except DockerError as e:
        raise RemapError(f"cannot ask the Docker daemon whether it is remapped: {e}") from e
    except json.JSONDecodeError as e:
        raise RemapError(f"docker info returned output that is not JSON: {e}") from e
    if not isinstance(doc, dict):
        raise RemapError("docker info returned JSON that is not a JSON object")
    return doc


def daemon_json_userns(etc: Path) -> str | None:
    """The userns-remap value in daemon.json, or None (also for "", which
    Docker reads as remapping off)."""
    path = etc / "docker" / "daemon.json"
    try:
        raw = path.read_text()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as e:
        raise RemapError(f"cannot read {path}: {e}") from e
    try:
        doc = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as e:
        raise RemapError(f"{path} is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise RemapError(f"{path} is not a JSON object")
    value = doc.get("userns-remap")
    if value is not None and not isinstance(value, str):
        raise RemapError(f"{path}: userns-remap must be a string, got {value!r}")
    return value or None


def _daemon_remapped(info: dict[str, Any]) -> bool:
    return "name=userns" in (info.get("SecurityOptions") or [])


def boxmunge_claims_remap(paths: BoxPaths) -> bool:
    """Does a readable boxmunge source say this box is remapped: the
    boxmunge.yml record, or daemon.json naming boxmunge's identity?

    A source that cannot be read claims nothing here; remap_offset still
    names it. A daemon remapped with another identity (Docker's "default")
    is not boxmunge's remap: the migration refuses it (OPERATIONS.md).
    """
    try:
        if recorded_offset(paths) is not None:
            return True
    except RemapError:
        pass
    try:
        return daemon_json_userns(ETC) == DAEMON_REMAP_VALUE
    except RemapError:
        return False


def daemon_remapped(paths: BoxPaths) -> bool:
    """Does the running daemon remap user namespaces? The rules about what
    it can start depend only on that. When boxmunge claims the remap, every
    source must agree (remap_offset); otherwise only the daemon is asked."""
    if boxmunge_claims_remap(paths):
        return remap_offset(paths) != 0
    return _daemon_remapped(docker_info())


def remap_offset(paths: BoxPaths) -> int:
    """S when the box is remapped as recorded, 0 when it was never remapped.

    Raises RemapError, naming every source that disagrees, otherwise.
    """
    record = recorded_offset(paths)
    configured = daemon_json_userns(ETC)
    info = docker_info()
    remapped = _daemon_remapped(info)
    if record is None and configured is None and not remapped:
        return 0
    problems = []
    if record is None:
        problems.append(f"{paths.config_file} has no userns record")
    if configured != DAEMON_REMAP_VALUE:
        problems.append(f"daemon.json userns-remap is {configured!r}, not {DAEMON_REMAP_VALUE!r}")
    if not remapped:
        problems.append("the running daemon is not remapped (docker info has no name=userns)")
    if info.get("Driver") != "overlay2":
        problems.append(f"the daemon's storage driver is {info.get('Driver')!r}, not 'overlay2'")
    if record is not None:
        for what, ranges in zip(("subuid", "subgid"), remap_ranges(ETC)):
            got = [(r.start, r.count) for r in ranges]
            if got != [(record, RANGE)]:
                problems.append(f"{ETC / what} gives {REMAP_NAME} {got}, not [({record}, {RANGE})]")
        root = str(info.get("DockerRootDir") or "")
        if not root.endswith(f"/{record}.{record}"):
            problems.append(f"the daemon's root dir is {root!r}, not .../{record}.{record}")
    if problems:
        raise RemapError("user-namespace remapping is inconsistent: " + "; ".join(problems)
                         + ". See OPERATIONS.md, 'User-namespace remapping'.")
    return record
