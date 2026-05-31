#!/usr/bin/env python3
"""Build a deterministic source bundle tarball.

Replaces `tar czf` in the Makefile. `tar czf` is non-deterministic in
two ways that broke the v0.10 reproducibility acceptance criterion:

1. gzip embeds a build timestamp in its header.
2. tar records each file's mtime / uid / gid from disk; `cp -r` resets
   directory mtimes on every build, so consecutive runs produce
   different headers even when the source tree is unchanged.

This script normalises every tar entry (mtime=0, uid=gid=0, uname=gname='',
sorted alphabetically) and writes through a gzip stream with mtime=0.
Two runs against the same source tree produce byte-identical archives.

Usage: build-bundle.py <output.tar.gz> <stage-dir> <archive-root-name>

Example:
    build-bundle.py dist/boxmunge-0.9.2.tar.gz dist/.stage boxmunge
"""
from __future__ import annotations

import gzip
import io
import sys
import tarfile
from pathlib import Path


def _add_path(tar: tarfile.TarFile, abs_path: Path, arcname: str) -> None:
    """Add a single path (file or dir) to the tar with normalised metadata."""
    info = tar.gettarinfo(str(abs_path), arcname=arcname)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    # Preserve mode bits (executable matters), but normalise the high bits.
    info.mode = info.mode & 0o7777
    if info.isfile():
        with open(abs_path, "rb") as f:
            tar.addfile(info, f)
    else:
        tar.addfile(info)


def _walk_sorted(root: Path) -> list[tuple[Path, str]]:
    """Walk `root` and return (abs_path, arcname) pairs, sorted by arcname.

    Directories appear before their contents.
    """
    entries: list[tuple[Path, str]] = []
    root_name = root.name
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root.parent).as_posix()):
        arcname = path.relative_to(root.parent).as_posix()
        entries.append((path, arcname))
    # rglob doesn't include `root` itself — add it first.
    entries.insert(0, (root, root_name))
    return entries


def main() -> int:
    if len(sys.argv) != 4:
        sys.stderr.write(
            "usage: build-bundle.py <output.tar.gz> <stage-dir> <archive-root-name>\n"
        )
        return 2

    out_path = Path(sys.argv[1])
    stage_dir = Path(sys.argv[2])
    archive_root = sys.argv[3]
    root = stage_dir / archive_root

    if not root.is_dir():
        sys.stderr.write(f"ERROR: stage root not found: {root}\n")
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Build the tar in-memory, then write through a gzip stream with mtime=0.
    # Doing it in two phases avoids any gzip-side mtime leakage.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for abs_path, arcname in _walk_sorted(root):
            _add_path(tar, abs_path, arcname)

    with open(out_path, "wb") as f, gzip.GzipFile(
        fileobj=f, mode="wb", mtime=0, compresslevel=9
    ) as gz:
        gz.write(buf.getvalue())

    return 0


if __name__ == "__main__":
    sys.exit(main())
