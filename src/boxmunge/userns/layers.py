# SPDX-License-Identifier: Apache-2.0
"""Ids >= 65536 in an image's layers, read from a `docker save` stream.

Such an image can never be loaded or pulled on a remapped daemon, and in a
tar holding several images it aborts the load of the ones after it (E20).
Layers come plain, gzip-compressed (the containerd store keeps compressed
blobs) or zstd-compressed, which this reader refuses rather than skips.
"""
from __future__ import annotations

import gzip
import io
import subprocess
import tarfile
from typing import IO, Iterator

from boxmunge.docker_run import docker_env

RANGE = 65536
_GZIP = b"\x1f\x8b"
_ZSTD = b"\x28\xb5\x2f\xfd"
_SAVE_TIMEOUT = 1800


class LayerScanError(Exception):
    """An image's layers cannot be read."""


class _Prefixed(io.RawIOBase):
    """`head` and then the rest of `rest`, as one stream."""

    def __init__(self, head: bytes, rest: IO[bytes]) -> None:
        self._head, self._rest = head, rest

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:  # type: ignore[override]
        if self._head:
            n = min(len(b), len(self._head))
            b[:n], self._head = self._head[:n], self._head[n:]
            return n
        data = self._rest.read(len(b))
        b[:len(data)] = data
        return len(data)


def _layer_entries(member: IO[bytes], name: str) -> Iterator[tarfile.TarInfo]:
    head = member.read(512)
    stream = io.BufferedReader(_Prefixed(head, member))
    if head[:2] == _GZIP:
        inner: IO[bytes] = gzip.GzipFile(fileobj=stream)  # type: ignore[assignment]
    elif head[:4] == _ZSTD:
        raise LayerScanError(f"{name} is a zstd-compressed layer, which boxmunge cannot read")
    elif len(head) >= 262 and head[257:262] == b"ustar":
        inner = stream
    else:
        return  # a config or manifest blob, not a layer
    with tarfile.open(fileobj=inner, mode="r|") as tar:
        yield from tar


def high_ids(save_stream: IO[bytes]) -> list[str]:
    """`path (uid:gid)` of every layer entry with an id >= 65536."""
    found: list[str] = []
    try:
        with tarfile.open(fileobj=save_stream, mode="r|") as outer:
            for member in outer:
                if not member.isfile():
                    continue
                f = outer.extractfile(member)
                if f is None:
                    raise LayerScanError(f"{member.name} cannot be read from the image tar")
                for entry in _layer_entries(f, member.name):
                    if entry.uid >= RANGE or entry.gid >= RANGE:
                        found.append(f"{entry.name} ({entry.uid}:{entry.gid})")
    except (tarfile.TarError, EOFError, OSError) as e:
        raise LayerScanError(f"the image tar cannot be read: {e}") from e
    return found


def image_high_ids(image_id: str) -> list[str]:
    proc = subprocess.Popen(["docker", "save", image_id], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=docker_env())
    assert proc.stdout is not None
    scan_error: LayerScanError | None = None
    try:
        found = high_ids(proc.stdout)
    except LayerScanError as e:
        scan_error, found = e, []
    finally:
        proc.stdout.close()
        _out, err = proc.communicate(timeout=_SAVE_TIMEOUT)
    if proc.returncode != 0:
        raise LayerScanError(f"docker save {image_id[:19]} failed: "
                             f"{err.decode(errors='replace').strip()}")
    if scan_error is not None:
        raise scan_error
    return found
