"""Layer id scan on synthetic docker-save tars."""
from __future__ import annotations

import gzip
import io
import tarfile

import pytest

from boxmunge.userns.layers import LayerScanError, high_ids


def _layer(uid: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("etc/f")
        info.uid = info.gid = uid
        data = b"x"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _save(*blobs: tuple[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in blobs:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


def test_plain_and_gzip_layers_are_read_and_json_skipped() -> None:
    stream = _save(("manifest.json", b'[{"Layers": []}]'),
                   ("blobs/sha256/a", _layer(0)),
                   ("blobs/sha256/b", gzip.compress(_layer(70000))))
    assert high_ids(stream) == ["etc/f (70000:70000)"]


def test_ids_inside_the_range_are_fine() -> None:
    assert high_ids(_save(("blobs/sha256/a", _layer(65535)))) == []


def test_zstd_layers_are_refused_not_skipped() -> None:
    with pytest.raises(LayerScanError, match="zstd"):
        high_ids(_save(("blobs/sha256/z", b"\x28\xb5\x2f\xfd" + b"\0" * 600)))


def test_a_truncated_save_is_refused() -> None:
    whole = _save(("blobs/sha256/a", gzip.compress(_layer(0)))).getvalue()
    with pytest.raises(LayerScanError, match="cannot be read"):
        high_ids(io.BytesIO(whole[:700]))
