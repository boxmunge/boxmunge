"""Bundle extraction and the bundle content policy.

Installing a checked tree into a project lives in boxmunge.release.
"""
from __future__ import annotations

import gzip
import os
import posixpath
import shutil
import tarfile
from pathlib import Path
from typing import IO, Any


class BundleError(ValueError):
    """A bundle is malformed or carries content a deploy must not install."""


# How far a bundle may expand, enforced while its archive is read. A small
# .tar.gz can expand without bound: into files that would fill the disk
# under the project's incoming workspace, into millions of entries whose
# headers tarfile holds in memory, or into extended (PAX, GNU long-name)
# headers that tarfile reads into memory whole. So each entry is checked as
# its header arrives (_read_members), each extended header before its body
# is read and a sparse member (whose map tarfile holds in memory) outright
# (_CheckedTarInfo), and the decompressed stream refuses any position past
# what those limits allow (_LimitedStream), whatever else a header makes
# tarfile read. Nothing is written, and no more than that is held, before
# the limits pass.
MAX_TOTAL_BYTES = 4 * 1024 ** 3
MAX_MEMBER_BYTES = 2 * 1024 ** 3
MAX_MEMBERS = 100_000
# An extended header holds a long path or link, some xattrs, or (git
# archive's global header) a commit id.
MAX_EXTENDED_HEADER_BYTES = 1024 ** 2
MAX_EXTENDED_TOTAL_BYTES = 128 * 1024 ** 2
# Archive bytes per entry beyond its contents and extended headers: its
# header block and its padding to a 512-byte block.
HEADER_ALLOWANCE = 1024
_SHRINK = ("Leave build output, dependencies and data out of the bundle (list them in "
           ".boxmungeignore), then bundle and upload it again.")
_GNU_SPARSE = tarfile.GNUTYPE_SPARSE
_EXTENDED = (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
             tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK)


def _size(n: int) -> str:
    for unit, scale in (("GiB", 1024 ** 3), ("MiB", 1024 ** 2)):
        if n >= scale:
            return f"{n / scale:.1f} {unit}"
    return f"{n} bytes"


class _LimitedStream:
    """A bundle's decompressed archive, for tarfile: refuses any position
    past the contents, headers and extended headers the limits allow, and
    counts the extended header bytes read."""

    def __init__(self, raw: IO[bytes]) -> None:
        self._raw = raw
        self._limit = (MAX_TOTAL_BYTES + MAX_MEMBERS * HEADER_ALLOWANCE
                       + MAX_EXTENDED_TOTAL_BYTES)
        self._extended = 0

    def note_extended(self, info: tarfile.TarInfo) -> None:
        """An extended header is about to be read: refuse one too large,
        or one past the total extended headers may take."""
        if info.size > MAX_EXTENDED_HEADER_BYTES:
            raise BundleError(f"Bundle has an extended (PAX or long-name) header of "
                              f"{_size(info.size)}; one may be at most "
                              f"{_size(MAX_EXTENDED_HEADER_BYTES)}. {_SHRINK}")
        self._extended += info.size
        if self._extended > MAX_EXTENDED_TOTAL_BYTES:
            raise BundleError(f"Bundle's extended (PAX or long-name) headers come to more "
                              f"than {_size(MAX_EXTENDED_TOTAL_BYTES)}, the most a bundle "
                              f"may carry. {_SHRINK}")

    def read(self, size: int = -1) -> bytes:
        left = self._limit - self._raw.tell()
        data = self._raw.read(left + 1 if size < 0 else min(size, left + 1))
        if len(data) > left:
            raise BundleError(f"Bundle's archive runs past {_size(self._limit)}, more "
                              f"than its limits allow. {_SHRINK}")
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._raw.seek(offset, whence)

    def tell(self) -> int:
        return self._raw.tell()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


def _sparse(name: str) -> BundleError:
    return BundleError(
        f"Bundle entry '{name}' is a sparse file; bundles may contain only files, "
        f"directories and links. Re-create the bundle with `boxmunge bundle` and upload "
        f"it again.")


class _CheckedTarInfo(tarfile.TarInfo):
    """Every header tarfile parses (an entry's, and each extended header
    chained before it) passes _proc_member, before any body is read. A
    sparse member is refused before its map is read: tarfile holds the map
    in memory (old-GNU extension blocks, or a PAX 1.0 map in the member's
    body) before any limit sees the member, and `boxmunge bundle` never
    writes one. The _proc_* hooks have these signatures on 3.11 to 3.13."""

    def _proc_member(self, tarfile):  # noqa: ANN001 — tarfile's own signature
        if self.type == _GNU_SPARSE:
            raise _sparse(self.name)
        if self.type in _EXTENDED:
            tarfile.fileobj.note_extended(self)
        return super()._proc_member(tarfile)

    def _proc_sparse(self, tarfile):  # noqa: ANN001
        raise _sparse(self.name)

    def _proc_gnusparse_00(self, next, raw_headers):  # noqa: ANN001, A002
        raise _sparse(next.name)

    def _proc_gnusparse_01(self, next, pax_headers):  # noqa: ANN001, A002
        raise _sparse(next.name)

    def _proc_gnusparse_10(self, next, pax_headers, tarfile):  # noqa: ANN001, A002
        raise _sparse(next.name)


def _read_members(tar: tarfile.TarFile) -> list[tarfile.TarInfo]:
    """Every member, each header checked against the limits as it arrives:
    at most MAX_MEMBERS entries, no file over MAX_MEMBER_BYTES, and at most
    MAX_TOTAL_BYTES in all."""
    members: list[tarfile.TarInfo] = []
    total = 0
    for m in tar:
        members.append(m)
        if len(members) > MAX_MEMBERS:
            raise BundleError(f"Bundle has more than {MAX_MEMBERS} entries; a bundle may "
                              f"have at most {MAX_MEMBERS}. {_SHRINK}")
        if m.size > MAX_MEMBER_BYTES:
            raise BundleError(f"Bundle entry '{m.name}' is {_size(m.size)}; a file in a "
                              f"bundle may be at most {_size(MAX_MEMBER_BYTES)}. {_SHRINK}")
        total += m.size
        if total > MAX_TOTAL_BYTES:
            raise BundleError(f"Bundle expands to more than {_size(MAX_TOTAL_BYTES)}; a "
                              f"bundle may expand to at most {_size(MAX_TOTAL_BYTES)}. "
                              f"{_SHRINK}")
    return members


def _member_parts(name: str) -> list[str]:
    return [p for p in name.split("/") if p not in ("", ".")]


def _within(path: str, top: str) -> bool:
    return path == top or path.startswith(top + "/")


def _climbs_after_name(target: str) -> bool:
    """True if a link target has a `..` after a real name (``s/..``).

    Such a target is only safe if every name before the `..` is a real
    directory; when one is itself a link, a chain of individually harmless
    links climbs out of the project. Leading `..` segments are fine.
    """
    seen_name = False
    for part in target.split("/"):
        if part == "..":
            if seen_name:
                return True
        elif part not in ("", "."):
            seen_name = True
    return False


def _escaping_link(m: tarfile.TarInfo, target: str) -> BundleError:
    return BundleError(
        f"Bundle entry '{m.name}' is a link to '{target}', outside the "
        f"project directory; bundles may only contain links that stay "
        f"inside the project"
    )


def _check_members(members: list[tarfile.TarInfo]) -> str:
    """Validate archive members before anything is written; return the top dir.

    Every member must live under one top-level directory, be a regular file,
    directory or link, and every link must resolve inside that directory.
    """
    tops: set[str] = set()
    for m in members:
        if m.name.startswith("/") or ".." in m.name.split("/"):
            raise BundleError(f"Unsafe path in bundle: {m.name}")
        parts = _member_parts(m.name)
        if not parts:
            continue
        tops.add(parts[0])
        if not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
            raise BundleError(
                f"Bundle entry '{m.name}' is a device, FIFO or other special "
                f"file; bundles may only contain files, directories and links"
            )
    if len(tops) != 1:
        raise BundleError(
            f"Bundle must contain exactly one top-level directory, "
            f"found: {sorted(tops)}"
        )
    top = tops.pop()
    for m in members:
        if not (m.issym() or m.islnk()):
            continue
        name = "/".join(_member_parts(m.name))
        target = m.linkname
        if m.issym():
            if _climbs_after_name(target):
                raise _escaping_link(m, target)
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(name), target))
        else:
            if ".." in target.split("/"):
                raise _escaping_link(m, target)
            resolved = posixpath.normpath("/".join(_member_parts(target)))
        if target.startswith("/") or not _within(resolved, top):
            raise _escaping_link(m, target)
    return top


def check_extracted_links(project: Path) -> None:
    """Resolve every link in an extracted project on disk; all must stay inside.

    The member checks reason about each link lexically. This walks the real
    tree, where links can chain, and requires ``realpath`` of every link to
    land inside the project.
    """
    root = os.path.realpath(project)
    for dirpath, dirnames, filenames in os.walk(project):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            if not os.path.islink(path):
                continue
            real = os.path.realpath(path)
            if real != root and not real.startswith(root + os.sep):
                rel = os.path.relpath(path, project)
                raise BundleError(
                    f"Bundle entry '{rel}' is a link that resolves outside the "
                    f"project directory; bundles may only contain links that "
                    f"stay inside the project"
                )


def extract_bundle(bundle_path: Path, dest: Path) -> Path:
    """Extract a tar.gz bundle into dest and return the project directory.

    Raises BundleError (a ValueError) for anything unsafe or malformed: a
    corrupt archive, one over the size limits, members outside a single
    top-level directory, special files, or links that resolve outside the
    project.
    """
    if not bundle_path.exists():
        raise BundleError(f"Bundle not found: {bundle_path}")
    try:
        with gzip.open(bundle_path, "rb") as raw, \
                tarfile.open(fileobj=_LimitedStream(raw), mode="r:",
                             tarinfo=_CheckedTarInfo) as tar:
            members = _read_members(tar)
            top = _check_members(members)
            # The "data" filter re-checks links against the real filesystem
            # as it extracts: defence in depth behind _check_members.
            tar.extractall(path=dest, members=members, filter="data")
    except BundleError:
        raise
    except (tarfile.TarError, EOFError, OSError) as e:
        raise BundleError(f"Not a valid tar.gz bundle: {bundle_path.name}: {e}") from e

    project = dest / top
    if project.is_symlink() or not project.is_dir():
        raise BundleError(
            f"Bundle must contain exactly one top-level directory; "
            f"'{top}' is not a directory"
        )
    check_extracted_links(project)
    return project


# Top-level project entries owned by the box, never by a bundle. Each maps to
# the reason shown when a bundle carries it. A deploy that installed them
# would silently replace live secrets, CVE suppressions and their audit
# history (B-15), production data, or encrypted snapshots.
BOX_OWNED_ENTRIES: dict[str, str] = {
    "secrets.env": "secrets are managed on the server with "
                   "'secrets set <project> KEY=VALUE'",
    "security": "CVE suppressions and their audit history are managed on the "
                "server with 'security suppress' and 'security unsuppress'",
    "data": "the project's live data lives here on the server",
    "backups": "the server's encrypted snapshots live here",
    "caddy.override.conf": "it replaces the generated Caddy config verbatim, so "
                           "only an operator may place it, directly on the "
                           "server",
}

# Entries boxmunge itself creates in a project directory.
BOXMUNGE_ENTRIES: dict[str, str] = {
    "repo": "repo/ is the clone of a git-sourced project; a bundle must not "
            "ship one",
    ".releases": "boxmunge's release workspace",
    "compose.boxmunge.yml": "generated by boxmunge at deploy time",
    # Staging's own files live in the slot (.releases/staged/). These two
    # names are reserved for the files of a stage 0.10.1 or earlier made
    # (unresolved_stage); delete them with it once the upgrade floor is 0.11.7.
    "compose.boxmunge-staging.yml": "reserved for a 0.10.1 stage's generated files",
    "compose.staging-base.yml": "reserved for a 0.10.1 stage's generated files",
}

# Directories that may ship as empty placeholders (data/.gitkeep is a common
# repo convention). They carry nothing, so they are dropped with a note.
_PLACEHOLDER_DIRS = frozenset({"data", "backups", "security"})

# Staging keeps its copy of a project entry as ``<entry>-staging`` beside it
# (staging_copies): a release's own top-level ``foo-staging`` would be what
# staging mounts for ``./foo``, and what unstage removes.
STAGING_SUFFIX = "-staging"
STAGING_SUFFIX_REASON = ("the -staging suffix is reserved for staging's copies of the "
                          "project's entries; rename it")
_PLACEHOLDER_FILES = frozenset({".gitkeep", ".keep"})


def is_placeholder(path: Path) -> bool:
    """True for a real dir holding only dirs and empty .gitkeep/.keep files."""
    if path.is_symlink() or not path.is_dir():
        return False
    for p in path.rglob("*"):
        if p.is_symlink():
            return False
        if p.is_dir():
            continue
        if p.name not in _PLACEHOLDER_FILES or p.stat().st_size != 0:
            return False
    return True


def check_bundle_contents(tree: Path) -> list[str]:
    """Enforce the bundle content policy on an extracted tree.

    Drops empty placeholder dirs (returning a note for each) and raises
    BundleError naming every entry the bundle may not carry: box-owned and
    boxmunge's own entries, and any top-level ``*-staging`` name.
    """
    notes: list[str] = []
    refused: list[str] = []
    for entry in sorted(tree.iterdir(), key=lambda p: p.name):
        name = entry.name
        reason = BOX_OWNED_ENTRIES.get(name) or BOXMUNGE_ENTRIES.get(name)
        if reason is None and name.endswith(STAGING_SUFFIX):
            reason = STAGING_SUFFIX_REASON
        if reason is None:
            continue
        if name in _PLACEHOLDER_DIRS and is_placeholder(entry):
            shutil.rmtree(entry)
            notes.append(f"NOTE: ignoring the bundle's empty placeholder {name}/ "
                         f"(the server's {name}/ is kept)")
            continue
        label = f"{name}/" if entry.is_dir() and not entry.is_symlink() else name
        refused.append(f"  {label}: {reason}")
    if refused:
        raise BundleError(
            "Bundle contains entries a bundle may not carry:\n"
            + "\n".join(refused)
            + "\nRemove (or rename) them in the bundle and upload it again."
        )
    return notes
