"""Bundle extraction and the bundle content policy.

Installing a checked tree into a project lives in boxmunge.release.
"""
from __future__ import annotations

import os
import posixpath
import shutil
import tarfile
from pathlib import Path


class BundleError(ValueError):
    """A bundle is malformed or carries content a deploy must not install."""


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
    corrupt archive, members outside a single top-level directory, special
    files, or links that resolve outside the project.
    """
    if not bundle_path.exists():
        raise BundleError(f"Bundle not found: {bundle_path}")
    try:
        with tarfile.open(bundle_path, "r:gz") as tar:
            top = _check_members(tar.getmembers())
            # The "data" filter re-checks links against the real filesystem
            # as it extracts: defence in depth behind _check_members.
            tar.extractall(path=dest, filter="data")
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
}

# Entries boxmunge itself creates in a project directory.
BOXMUNGE_ENTRIES: dict[str, str] = {
    "repo": "repo/ is the clone of a git-sourced project; a bundle must not "
            "ship one",
    ".releases": "boxmunge's release workspace",
    "compose.boxmunge.yml": "generated by boxmunge at deploy time",
    "compose.boxmunge-staging.yml": "generated by boxmunge at stage time",
    "compose.staging-base.yml": "generated by boxmunge at stage time",
}

# Directories that may ship as empty placeholders (data/.gitkeep is a common
# repo convention). They carry nothing, so they are dropped with a note.
_PLACEHOLDER_DIRS = frozenset({"data", "backups", "security"})
_PLACEHOLDER_FILES = frozenset({".gitkeep", ".keep"})


def _is_placeholder(path: Path) -> bool:
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
    BundleError naming every entry the bundle may not carry.
    """
    notes: list[str] = []
    refused: list[str] = []
    for entry in sorted(tree.iterdir(), key=lambda p: p.name):
        name = entry.name
        reason = BOX_OWNED_ENTRIES.get(name) or BOXMUNGE_ENTRIES.get(name)
        if reason is None:
            continue
        if name in _PLACEHOLDER_DIRS and _is_placeholder(entry):
            shutil.rmtree(entry)
            notes.append(f"NOTE: ignoring the bundle's empty placeholder {name}/ "
                         f"(the server's {name}/ is kept)")
            continue
        label = f"{name}/" if entry.is_dir() and not entry.is_symlink() else name
        refused.append(f"  {label}: {reason}")
    if refused:
        raise BundleError(
            "Bundle contains entries a deploy must never overwrite:\n"
            + "\n".join(refused)
            + "\nRemove them from the bundle and upload it again."
        )
    return notes
