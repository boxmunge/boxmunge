# SPDX-License-Identifier: Apache-2.0
"""A project's bind sources, checked without following symlinks.

Docker resolves a bind source each time it starts a container, following
symlinks anywhere in the path, and creates a missing source as root,
through whatever symlinks lead there. A container that can write the
directory holding one of its project's bind sources can therefore point
that mount at `/` for the next start. Compose validation compares paths as
text, so it cannot see this; these checks walk the real filesystem.

Each source is walked from the project directory one component at a time
with lstat and O_NOFOLLOW: no component may be a symlink, and the source
must be a directory or a regular file. Deploy and stage record the kind of
every source they start with (`state/deploy/<project>.binds.json`, outside
the project, so no container can write it), creating missing sources as
plain directories first, as Docker would have. Every later start finds
each source still there, of the same kind.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Iterable

from boxmunge.compose_mounts import host_path_forms, is_bind_entry, volume_source
from boxmunge.compose_own_files import CONTROL_ENTRIES
from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import open_regular_nofollow

DIR = "dir"
FILE = "file"
# A bind source that is neither a directory nor a regular file — a socket or
# FIFO an app created in its data directory, say. Allowed (it is the
# container's own file, not one boxmunge reads) but still recorded, so a
# later change of kind is caught.
SPECIAL = "special"
_KINDS = (DIR, FILE, SPECIAL)
RECORD_VERSION = 2

# CONTROL_ENTRIES that are files worth hashing. The directories among them
# (security/, .releases/, boxmunge-scripts/, repo/.git) are guarded by the
# bind-mount rules, not by content hashing. secrets.env is not hashed either:
# `secrets set` rewrites it between deploys, and its values reach only the
# containers' environments; the bind-mount rules keep containers off it.
_UNHASHED = frozenset({"secrets.env"})
_CONTROL_FILES = tuple(
    e for e in CONTROL_ENTRIES
    if e not in ("security", ".releases", "boxmunge-scripts", "repo/.git") and e not in _UNHASHED
)
OVERLAY = "compose.boxmunge.yml"


class BindSourceError(Exception):
    """A bind source is missing, outside the project, reached through a
    symlink, or not what deploy recorded."""


def model_sources(model: dict[str, Any], project_dir: Path) -> set[str]:
    """Project-relative path of every host path a compose model mounts:
    service bind mounts and the files of top-level secrets and configs."""
    sources: set[str] = set()
    for svc in (model.get("services") or {}).values():
        if not isinstance(svc, dict) or not isinstance(svc.get("volumes"), list):
            continue
        for entry in svc["volumes"]:
            src = volume_source(entry)
            if src is not None and is_bind_entry(entry):
                sources.add(project_rel(host_path_forms(src, project_dir)[0], project_dir))
    for section in ("secrets", "configs"):
        entries = model.get(section)
        for decl in (entries.values() if isinstance(entries, dict) else ()):
            path = decl.get("file") if isinstance(decl, dict) else None
            if isinstance(path, str):
                sources.add(project_rel(host_path_forms(path, project_dir)[0], project_dir))
    return sources


def project_rel(source: str, project_dir: Path) -> str:
    """`source` relative to the project directory, without resolving any
    symlink below it. Raises BindSourceError for a path outside it."""
    norm = os.path.normpath(source)
    for root in {os.path.normpath(project_dir), os.path.realpath(project_dir)}:
        if norm == root or norm.startswith(root + "/"):
            return os.path.relpath(norm, root)
    raise BindSourceError(f"bind source {source} is outside the project directory {project_dir}")


def _kind(st: os.stat_result, shown: str) -> str:
    if stat.S_ISDIR(st.st_mode):
        return DIR
    if stat.S_ISREG(st.st_mode):
        return FILE
    return SPECIAL


def source_kind(project_dir: Path, rel: str, *, create: bool) -> str:
    """Walk `rel` from the project directory without following symlinks and
    return the kind of what it names. `create` makes missing components
    (and a missing source) plain directories, as Docker would."""
    if rel == ".":
        return DIR
    parts = rel.split("/")
    fd = os.open(project_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for i, part in enumerate(parts):
            shown = "/".join(parts[:i + 1])
            try:
                st = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise BindSourceError(
                        f"bind source {rel} does not exist ({shown} is missing)") from None
                os.mkdir(part, 0o755, dir_fd=fd)
                st = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                raise BindSourceError(
                    f"bind source {rel}: {shown} is a symlink, which Docker would "
                    f"follow to wherever it points")
            if i == len(parts) - 1:
                return _kind(st, rel)
            if not stat.S_ISDIR(st.st_mode):
                raise BindSourceError(f"bind source {rel}: {shown} is not a directory")
            # O_NOFOLLOW: a symlink swapped in since the lstat is refused too.
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as e:
                raise BindSourceError(f"bind source {rel}: cannot open {shown}: {e}") from e
            os.close(fd)
            fd = nxt
    finally:
        os.close(fd)
    raise AssertionError("unreachable")


def control_hashes(project_dir: Path, read_files: Iterable[Path], *,
                   control_root: Path | None = None) -> dict[str, str | None]:
    """sha256 of every file boxmunge reads for the project, keyed by its
    project-relative path: the control files (compose, manifest, env files,
    the generated overlays) of `control_root` (the release the start runs:
    the project dir, or staging's slot) and the compose/include/extends/
    env/label files `read_files` names. An absent tracked file is `None`, so
    one created after deploy is a mismatch. A control file that is a symlink
    (a git project's compose.yml and manifest.yml link into repo/) is hashed
    through its target, together with the target's path, as long as the
    fully resolved target stays inside the project; a link out of it is
    refused."""
    hashes: dict[str, str | None] = {}
    root = control_root or project_dir
    candidates: dict[str, Path] = {project_rel(str(root / e), project_dir): root / e
                                   for e in _CONTROL_FILES}
    for path in read_files:
        try:
            rel = project_rel(str(path), project_dir)
        except BindSourceError:
            continue  # outside the project; the reference walk already refused it
        if rel not in _UNHASHED:
            candidates[rel] = Path(path)
    for rel in sorted(candidates):
        hashes[rel] = _hash_file(project_dir, candidates[rel], rel)
    return hashes


def _hash_file(project_dir: Path, path: Path, rel: str) -> str | None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    h = hashlib.sha256()
    if stat.S_ISLNK(st.st_mode):
        root = os.path.realpath(project_dir)
        real = os.path.realpath(path)
        if real == root or not real.startswith(root + os.sep):
            raise BindSourceError(
                f"control file {rel} is a symlink that resolves to {real}, outside "
                f"the project directory; boxmunge only follows links that stay inside it")
        target = os.path.relpath(real, root)
        h.update(b"link:" + target.encode() + b"\0")
        fd = _open_in_project(root, target, rel)
    else:
        try:
            fd = open_regular_nofollow(path, os.O_RDONLY)
        except OSError as e:
            raise BindSourceError(
                f"control file {rel} cannot be read as a regular file ({e}); a "
                f"container may have replaced it with a special file") from e
    try:
        with os.fdopen(fd, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        raise BindSourceError(f"control file {rel} cannot be read: {e}") from e


def refresh_overlay_hash(project_dir: Path, path: Path) -> None:
    """Record the hash of the overlay boxmunge has just regenerated (resume,
    recover, security resume and rollback regenerate it outside a deploy).
    The overlay is derived from compose.yml and the manifest, whose own
    hashes are still checked, so recording boxmunge's own output blesses
    nothing a container wrote. No record yet: nothing to refresh."""
    if not path.exists():
        return
    doc = read_record(path)
    doc["control"][OVERLAY] = _hash_file(project_dir, project_dir / OVERLAY, OVERLAY)
    atomic_write_text(path, json.dumps(doc, indent=2) + "\n")
def _open_in_project(root: str, target: str, rel: str) -> int:
    """Open a control file's resolved target, one component at a time from
    the project root with O_NOFOLLOW, so a link swapped in after the
    realpath cannot redirect the read. The target must be a plain regular
    file."""
    parts = target.split(os.sep)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        out = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except OSError as e:
        raise BindSourceError(
            f"control file {rel}: its link target {target} cannot be opened "
            f"without following a further link ({e})") from e
    finally:
        os.close(fd)
    st = os.fstat(out)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(out)
        raise BindSourceError(
            f"control file {rel}: its link target {target} is not a plain regular file")
    return out


def read_record(path: Path) -> dict[str, Any]:
    """The bind sources, kinds and control hashes deploy recorded. Raises
    BindSourceError when there is no readable record."""
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        raise BindSourceError(
            f"no record of the bind sources this project was deployed with "
            f"({path}). Deploy it again to record them.") from None
    except (OSError, ValueError) as e:
        raise BindSourceError(f"cannot read {path}: {e}") from e
    sources = doc.get("sources") if isinstance(doc, dict) else None
    control = doc.get("control") if isinstance(doc, dict) else None
    if (not isinstance(doc, dict) or doc.get("version") != RECORD_VERSION
            or not isinstance(sources, dict)
            or not all(isinstance(k, str) and v in _KINDS for k, v in sources.items())
            or not isinstance(control, dict)
            or not all(isinstance(k, str) and (v is None or isinstance(v, str))
                       for k, v in control.items())):
        raise BindSourceError(f"{path} is not a bind source record")
    return doc


def check_sources(project_dir: Path, sources: set[str], record: dict[str, str]) -> None:
    """Every source exists, reached without a symlink, as the kind recorded."""
    for rel in sorted(sources):
        kind = source_kind(project_dir, rel, create=False)
        if rel not in record:
            raise BindSourceError(
                f"bind source {rel} was not mounted when the project was last "
                f"deployed. Deploy it to start it with new mounts.")
        if record[rel] != kind:
            raise BindSourceError(
                f"bind source {rel} was a {record[rel]} when the project was "
                f"deployed and is now a {kind}")


def check_control(
    project_dir: Path, read_files: Iterable[Path], record: dict[str, str | None], *,
    control_root: Path | None = None,
) -> None:
    """Every file boxmunge reads hashes to what deploy recorded. A rewritten
    control file (a tampered manifest or compose), or one newly created or
    removed, is refused: a later root `up` must never run container-modified
    control files."""
    now = control_hashes(project_dir, read_files, control_root=control_root)
    for rel in sorted(set(now) | set(record)):
        if now.get(rel) != record.get(rel):
            raise BindSourceError(
                f"control file {rel} changed since the project was deployed; "
                f"redeploy to run it. Boxmunge will not start a release from "
                f"files it did not validate.")


def record(
    project_dir: Path, sources: set[str], read_files: Iterable[Path], path: Path, *,
    control_root: Path | None = None,
) -> None:
    """Check every source, creating missing ones, record their kinds, and
    record the sha256 of every file boxmunge reads."""
    kinds = {rel: source_kind(project_dir, rel, create=True) for rel in sorted(sources)}
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps({
        "version": RECORD_VERSION, "sources": kinds,
        "control": control_hashes(project_dir, read_files, control_root=control_root),
    }, indent=2) + "\n")
