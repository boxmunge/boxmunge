# SPDX-License-Identifier: Apache-2.0
"""F10: reception inspects an upload with the same bounded reader as
extraction (bundle.inspect_bundle), in one forward pass, and caps the
manifest before YAML sees it. Whatever it refuses is a ValueError, and
nothing is filed in the inbox, so no later deploy can pick it up."""
from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

from boxmunge import bundle, reception
from boxmunge.bundle import BundleError, extract_bundle
from boxmunge.reception import peek_manifest_from_bundle, receive_bundle

MANIFEST = b"project: demo\n"


def _file(tar: tarfile.TarFile, name: str, data: bytes = b"x") -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def _upload(tmp_path: Path, extra=lambda tar: None, manifest: bytes | None = MANIFEST) -> Path:
    """An upload as the scp session leaves it: demo/manifest.yml, then
    whatever `extra` adds."""
    path = tmp_path / "session" / "upload.tar.gz"
    path.parent.mkdir(exist_ok=True)
    with tarfile.open(path, "w:gz") as tar:
        if manifest is not None:
            _file(tar, "demo/manifest.yml", manifest)
        extra(tar)
    return path


def _refused(upload: Path, paths, match: str) -> None:
    """Reception refuses with a ValueError, and files nothing."""
    with pytest.raises(ValueError, match=match):
        receive_bundle(upload, paths)
    assert not list(paths.inbox.rglob("*.tar.gz"))
    assert upload.exists()  # left for the session to remove with its directory


def _sparse(tar: tarfile.TarFile) -> None:
    info = tarfile.TarInfo("demo/hole")
    info.type = tarfile.GNUTYPE_SPARSE
    tar.addfile(info)


def _long_header(tar: tarfile.TarFile) -> None:
    info = tarfile.TarInfo("demo/././@LongLink")
    info.type = tarfile.GNUTYPE_LONGNAME
    info.size = 600
    tar.addfile(info, io.BytesIO(b"n" * 600))
    _file(tar, "demo/named")


@pytest.mark.parametrize("limit, value, extra, match", [
    # The audit's probe: five entries against a cap of three.
    ("MAX_MEMBERS", 3, lambda t: [_file(t, f"demo/file-{i}") for i in range(4)],
     "more than 3 entries"),
    ("MAX_MEMBER_BYTES", 100, lambda t: _file(t, "demo/blob", b"\0" * 101), "'demo/blob' is 101"),
    ("MAX_TOTAL_BYTES", 150, lambda t: [_file(t, f"demo/f{i}", b"\0" * 60) for i in range(3)],
     "expands to more than 150 bytes"),
    ("MAX_EXTENDED_HEADER_BYTES", 512, _long_header, "extended .* header of 600 bytes"),
    (None, None, _sparse, "sparse file"),
], ids=["entries", "one file", "total", "extended header", "sparse"])
def test_reception_refuses_what_extraction_refuses(tmp_path, paths, monkeypatch,
                                                   limit, value, extra, match) -> None:
    if limit:
        monkeypatch.setattr(bundle, limit, value)
    upload = _upload(tmp_path, extra)
    with pytest.raises(BundleError, match=match):
        extract_bundle(upload, tmp_path / "out")
    _refused(upload, paths, match)


def test_reception_refuses_a_layout_extraction_refuses(tmp_path, paths) -> None:
    upload = _upload(tmp_path, lambda t: _file(t, "other/manifest.yml", b"project: other\n"))
    _refused(upload, paths, "exactly one top-level directory")


def test_an_upload_within_the_limits_is_filed(tmp_path, paths) -> None:
    upload = _upload(tmp_path, lambda t: [_file(t, f"demo/file-{i}") for i in range(4)])
    dest = receive_bundle(upload, paths)
    assert dest.parent == paths.inbox and dest.name.startswith("demo-")
    assert extract_bundle(dest, tmp_path / "out") == tmp_path / "out" / "demo"


def test_an_oversized_manifest_never_reaches_yaml(tmp_path, paths, monkeypatch) -> None:
    monkeypatch.setattr(bundle, "MAX_MANIFEST_BYTES", 64)
    read: list[int] = []
    real = tarfile.TarFile.extractfile
    monkeypatch.setattr(tarfile.TarFile, "extractfile",
                        lambda self, m: read.append(m.size) or real(self, m))
    monkeypatch.setattr(reception.yaml, "safe_load",
                        lambda *_a: pytest.fail("the oversized manifest was parsed"))
    upload = _upload(tmp_path, manifest=b"project: demo\n" + b"# padding\n" * 10)
    _refused(upload, paths, "manifest.yml is 114 bytes; a manifest may be at most 64 bytes")
    assert read == []  # refused on its header, before a byte of it was read


def test_the_manifest_cap_leaves_room_for_real_manifests() -> None:
    assert 64 * 1024 <= bundle.MAX_MANIFEST_BYTES <= 1024 ** 2


@pytest.mark.parametrize("manifest, match", [
    (b"project: [unclosed\n", "not valid YAML"),
    (b"project: demo\n\tbad: tab\n", "not valid YAML"),
    (b"\xff\xfe\x00not text", "not valid YAML"),
    (b"[" * 20_000, "not valid YAML"),          # nesting past the parser's depth
    (b"- a\n- b\n", "not a YAML mapping"),
    (b"project: [a, b]\n", "'project' must be a project name"),
    (b"project: 7\n", "'project' must be a project name"),
    (b"hosts: []\n", "missing 'project'"),
], ids=["unclosed flow", "tab indent", "not text", "too deep", "a list", "project is a list",
        "project is a number", "no project"])
def test_a_malformed_manifest_is_a_reception_error(tmp_path, paths, manifest, match) -> None:
    _refused(_upload(tmp_path, manifest=manifest), paths, match)


def _damaged(tmp_path: Path, how: str) -> Path:
    whole = _upload(tmp_path, lambda t: _file(t, "demo/data", bytes(range(256)) * 64)).read_bytes()
    damaged = {
        "truncated": whole[:len(whole) // 2],
        "corrupt deflate stream": whole[:40] + b"\xff" * 64 + whole[104:],
        "gzip of something else": gzip.compress(b"not a tar archive at all\n" * 100),
        "not gzip": b"PK\x03\x04" + b"\0" * 600,
        "tar with a broken header": gzip.compress(b"demo/manifest.yml".ljust(512, b"\0") * 3),
    }[how]
    path = tmp_path / "session" / "damaged.tar.gz"
    path.write_bytes(damaged)
    return path


@pytest.mark.parametrize("how", ["truncated", "corrupt deflate stream", "gzip of something else",
                                 "not gzip", "tar with a broken header"])
def test_a_malformed_archive_is_a_reception_error(tmp_path, paths, how) -> None:
    _refused(_damaged(tmp_path, how), paths, "Not a valid tar.gz|No manifest.yml|top-level")


def test_reception_reads_the_archive_once_and_only_forward(tmp_path, paths, monkeypatch) -> None:
    """It used to open the archive twice (is_tarfile, then open), read every
    header, and seek back to the manifest, which makes gzip decompress from
    the start again."""
    opened: list[str] = []
    backward: list[tuple[int, int]] = []
    real_open, real_seek = gzip.open, bundle._LimitedStream.seek

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence != 0 or offset < self.tell():
            backward.append((self.tell(), offset))
        return real_seek(self, offset, whence)

    monkeypatch.setattr(bundle.gzip, "open", lambda *a, **k: opened.append("x") or real_open(*a, **k))
    monkeypatch.setattr(bundle._LimitedStream, "seek", seek)
    monkeypatch.setattr(tarfile, "is_tarfile", lambda *_a: pytest.fail("a second open"))
    monkeypatch.setattr(tarfile.TarFile, "getmembers", lambda *_a: pytest.fail("unbounded read"))
    upload = _upload(tmp_path, lambda t: [_file(t, f"demo/f{i}", b"y" * 3000) for i in range(20)])
    receive_bundle(upload, paths)
    assert opened == ["x"] and backward == []


def test_the_manifest_reception_reads_is_the_one_extraction_installs(tmp_path) -> None:
    """A name may appear twice in an archive; the later entry replaces the
    earlier on disk, so that is the manifest reception must judge."""
    upload = _upload(tmp_path, lambda t: _file(t, "demo/manifest.yml", b"project: later\n"))
    assert peek_manifest_from_bundle(upload) == {"project": "later"}
    tree = extract_bundle(upload, tmp_path / "out")
    assert (tree / "manifest.yml").read_bytes() == b"project: later\n"


def _manifest_link(tar: tarfile.TarFile) -> None:
    _file(tar, "demo/other.yml", b"project: other\n")
    info = tarfile.TarInfo("demo/manifest.yml")
    info.type = tarfile.SYMTYPE
    info.linkname = "other.yml"
    tar.addfile(info)


def test_a_manifest_replaced_by_a_later_link_is_not_the_manifest(tmp_path, paths) -> None:
    """Extraction leaves the later entry on disk, a link here, so the
    regular file before it is not what a deploy would read."""
    upload = _upload(tmp_path, _manifest_link)
    _refused(upload, paths, "No manifest.yml found")
    assert bundle.inspect_bundle(upload).manifest is None
