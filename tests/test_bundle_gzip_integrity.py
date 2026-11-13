"""A bundle's gzip stream must be whole and intact: a truncated stream, or one
whose trailer (CRC, length) is wrong, is a named refusal, even when the tar
inside reads cleanly. A full disk during extraction names its cause."""
from __future__ import annotations

import errno
import gzip
import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.bundle import BundleError, extract_bundle, inspect_bundle
from tests.bundle_helpers import SAFE_COMPOSE, manifest_text


def _tar_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tar:
        d = tarfile.TarInfo("myapp")
        d.type = tarfile.DIRTYPE
        tar.addfile(d)
        for name, data in (("myapp/manifest.yml", manifest_text().encode()),
                           ("myapp/compose.yml", SAFE_COMPOSE.encode())):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _gz(tmp_path: Path) -> bytes:
    return gzip.compress(_tar_bytes())


@pytest.mark.parametrize("call", [inspect_bundle, lambda p: extract_bundle(p, p.parent / "out")])
def test_a_bad_gzip_trailer_is_refused(tmp_path, call) -> None:
    raw = bytearray(_gz(tmp_path))
    raw[-8] ^= 0xFF  # the CRC32 in the trailer
    p = tmp_path / "b.tar.gz"
    p.write_bytes(bytes(raw))
    with pytest.raises(BundleError, match="Not a valid tar.gz bundle"):
        call(p)


@pytest.mark.parametrize("call", [inspect_bundle, lambda p: extract_bundle(p, p.parent / "out")])
def test_a_truncated_gzip_trailer_is_refused(tmp_path, call) -> None:
    p = tmp_path / "b.tar.gz"
    p.write_bytes(_gz(tmp_path)[:-4])
    with pytest.raises(BundleError, match="Not a valid tar.gz bundle"):
        call(p)


def test_a_full_disk_during_extraction_names_the_cause(tmp_path) -> None:
    p = tmp_path / "b.tar.gz"
    p.write_bytes(_gz(tmp_path))
    full = OSError(errno.ENOSPC, "No space left on device")
    with patch("tarfile.TarFile.extractall", side_effect=full):
        with pytest.raises(BundleError, match=r"(?i)out of disk space.*free (some )?space.*retry"):
            extract_bundle(p, tmp_path / "out")
