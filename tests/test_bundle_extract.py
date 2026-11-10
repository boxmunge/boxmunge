"""Bundle extraction safety: every refusal is a clean BundleError.

`extractall(filter="data")` raises tarfile.FilterError (not ValueError) for an
absolute or escaping link, which deploy did not catch: the operator got a
traceback instead of an ERROR line (audit E cross-area).
"""
from __future__ import annotations

import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.bundle import BundleError, extract_bundle
from boxmunge.commands.deploy import run_deploy
from boxmunge.project_registry import add_project

from tests.bundle_helpers import SAFE_COMPOSE, manifest_text


def _file(tar: tarfile.TarFile, name: str, data: bytes = b"x") -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def _link(tar: tarfile.TarFile, name: str, target: str, hard: bool = False) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.LNKTYPE if hard else tarfile.SYMTYPE
    info.linkname = target
    tar.addfile(info)


def _bundle(path: Path, extra) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        dir_info = tarfile.TarInfo("myapp")
        dir_info.type = tarfile.DIRTYPE
        tar.addfile(dir_info)
        _file(tar, "myapp/manifest.yml", manifest_text().encode())
        _file(tar, "myapp/compose.yml", SAFE_COMPOSE.encode())
        extra(tar)
    return path


@pytest.mark.parametrize("target", [
    "/etc/passwd",
    "../../etc/passwd",
    "../outside.txt",
    "sub/../../outside.txt",
])
def test_escaping_symlink_is_a_bundle_error(tmp_path: Path, target: str) -> None:
    bundle = _bundle(tmp_path / "b.tar.gz",
                     lambda t: _link(t, "myapp/link", target))
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(BundleError, match="myapp/link"):
        extract_bundle(bundle, dest)


def test_hardlink_outside_the_project_is_a_bundle_error(tmp_path: Path) -> None:
    def extra(t):
        _file(t, "other/secret.txt")
        _link(t, "myapp/hard", "other/secret.txt", hard=True)
    bundle = _bundle(tmp_path / "b.tar.gz", extra)
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(BundleError):
        extract_bundle(bundle, dest)


def test_internal_symlink_is_kept(tmp_path: Path) -> None:
    def extra(t):
        _file(t, "myapp/boxmunge-scripts/smoke.sh", b"#!/bin/sh\n")
        _link(t, "myapp/scripts", "boxmunge-scripts")
    bundle = _bundle(tmp_path / "b.tar.gz", extra)
    dest = tmp_path / "out"
    dest.mkdir()
    tree = extract_bundle(bundle, dest)
    assert (tree / "scripts").is_symlink()
    assert (tree / "scripts" / "smoke.sh").exists()


def test_member_outside_the_top_directory_is_refused(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "b.tar.gz", lambda t: _file(t, "stray.txt"))
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(BundleError, match="exactly one top-level directory"):
        extract_bundle(bundle, dest)


def test_device_file_is_refused(tmp_path: Path) -> None:
    def extra(t):
        info = tarfile.TarInfo("myapp/dev")
        info.type = tarfile.CHRTYPE
        t.addfile(info)
    bundle = _bundle(tmp_path / "b.tar.gz", extra)
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(BundleError, match="myapp/dev"):
        extract_bundle(bundle, dest)


def test_corrupt_archive_is_a_bundle_error(tmp_path: Path) -> None:
    good = _bundle(tmp_path / "b.tar.gz", lambda t: None)
    truncated = tmp_path / "t.tar.gz"
    truncated.write_bytes(good.read_bytes()[:60])
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(BundleError):
        extract_bundle(truncated, dest)


def test_deploy_reports_escaping_symlink_cleanly(paths, capsys) -> None:
    add_project("myapp", paths)
    _bundle(paths.inbox / "myapp-2026-10-13T100000000000.tar.gz",
            lambda t: _link(t, "myapp/link", "/etc/passwd"))
    with patch("boxmunge.compose_guard.compose_up") as up:
        rc = run_deploy("myapp", paths)
    assert rc == 1
    up.assert_not_called()
    err = capsys.readouterr().err
    assert err.startswith("ERROR:")
    assert "myapp/link" in err
    assert not paths.project_dir("myapp").exists()


def test_chained_links_cannot_climb_out(tmp_path: Path) -> None:
    """Each link looks harmless lexically on its own; chained, `l` resolves to
    the parent of the project and `m` climbs further (review finding)."""
    def extra(t):
        _link(t, "myapp/m", "l/..")      # ordered before the links it uses
        _link(t, "myapp/s", ".")
        _link(t, "myapp/l", "s/..")
    bundle = _bundle(tmp_path / "b.tar.gz", extra)
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(BundleError, match="myapp/(m|l)"):
        extract_bundle(bundle, dest)


@pytest.mark.parametrize("target", ["s/..", "a/../b", "./x/../../y"])
def test_dotdot_after_a_name_is_refused(tmp_path: Path, target: str) -> None:
    bundle = _bundle(tmp_path / "b.tar.gz",
                     lambda t: _link(t, "myapp/link", target))
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(BundleError, match="myapp/link"):
        extract_bundle(bundle, dest)


def test_leading_dotdot_inside_the_project_is_allowed(tmp_path: Path) -> None:
    def extra(t):
        _file(t, "myapp/conf/app.conf")
        _link(t, "myapp/sub/app.conf", "../conf/app.conf")
    bundle = _bundle(tmp_path / "b.tar.gz", extra)
    dest = tmp_path / "out"
    dest.mkdir()
    tree = extract_bundle(bundle, dest)
    assert (tree / "sub" / "app.conf").is_symlink()


def test_extracted_tree_check_resolves_links_on_disk(tmp_path: Path) -> None:
    """Defence in depth: after extraction every link is resolved with
    realpath and must stay inside the project."""
    from boxmunge.bundle import check_extracted_links
    project = tmp_path / "out" / "myapp"
    project.mkdir(parents=True)
    (project / "s").symlink_to(".")
    (project / "l").symlink_to("s/..")
    with pytest.raises(BundleError, match="l"):
        check_extracted_links(project)


def test_missing_bundle_is_a_bundle_error(tmp_path: Path) -> None:
    with pytest.raises(BundleError, match="not found"):
        extract_bundle(tmp_path / "nope.tar.gz", tmp_path)


@pytest.mark.parametrize("limit, value, extra, words", [
    ("MAX_MEMBER_BYTES", 1000, lambda t: _file(t, "myapp/blob.bin", b"\0" * 1001),
     ["'myapp/blob.bin'", "1001 bytes", "1000 bytes"]),
    ("MAX_TOTAL_BYTES", 1500, lambda t: [_file(t, f"myapp/f{i}", b"\0" * 400) for i in range(4)],
     ["expands to", "1500 bytes"]),
    ("MAX_MEMBERS", 5, lambda t: [_file(t, f"myapp/f{i}") for i in range(4)],
     ["more than 5 entries", "at most 5"]),
])
def test_a_bundle_over_a_size_limit_is_refused_before_anything_is_written(
        tmp_path, monkeypatch, limit, value, extra, words) -> None:
    """B-02: a small .tar.gz can expand without bound into the project's
    incoming workspace; each limit is checked on the headers first."""
    monkeypatch.setattr(f"boxmunge.bundle.{limit}", value)
    bundle = _bundle(tmp_path / "myapp.tar.gz", extra)
    dest = tmp_path / "incoming"
    with pytest.raises(BundleError) as e:
        extract_bundle(bundle, dest)
    text = str(e.value)
    assert all(w in text for w in words), text
    assert ".boxmungeignore" in text
    assert not dest.exists() or not any(dest.iterdir())


def test_the_limits_leave_room_for_real_projects() -> None:
    from boxmunge import bundle
    assert bundle.MAX_TOTAL_BYTES >= 4 * 1024 ** 3
    assert bundle.MAX_MEMBER_BYTES >= 2 * 1024 ** 3
    assert bundle.MAX_MEMBERS >= 100_000


# A GNU sparse member (tar --sparse): myapp/hole is 300000002 bytes with
# 258 of them stored, so its archive is a few hundred bytes.
_GNU_SPARSE = (
    "H4sIAKap8moAA+3R0QrCIBiGYY+7Cu8gdf56IV3BoMGIjUYW1d23NiIY7CTmBvE+J7+I6Idf+yy7bq+yMr0o"
    "Ms4wzt5nDmsrLnpxPvh+31oJUWnJG2t0S9fyorVKz3Q6pnb23L2uqmaNQOtqh/7rc1Ple+NdcPB+tn9v3KR/"
    "CYVX+pAv0tfm/Rtnoymcnf7I4g8seum/eOy2TgAAAAAAAAAAAAAAAAD87gVZwxyjACgAAA==")


def _pax_sparse(path: Path, records: dict[str, str], body: bytes = b"") -> Path:
    """A bundle whose myapp/s carries GNU's PAX sparse records."""
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as tar:
        top = tarfile.TarInfo("myapp")
        top.type = tarfile.DIRTYPE
        tar.addfile(top)
        info = tarfile.TarInfo("myapp/s")
        info.size = len(body)
        info.pax_headers = records
        tar.addfile(info, io.BytesIO(body))
    return path


_SPARSE_10 = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0",
              "GNU.sparse.name": "myapp/s", "GNU.sparse.realsize": "1"}


@pytest.mark.parametrize("kind", ["gnu", "pax-0.0", "pax-0.1", "pax-1.0"])
def test_a_sparse_member_is_refused(tmp_path, kind) -> None:
    """Review: tarfile reads a sparse map (old-GNU extension blocks, or a
    PAX 1.0 map in the member's body) into memory before any limit sees the
    member. `boxmunge bundle` never writes one, so none is accepted."""
    import base64
    bundle = tmp_path / "myapp.tar.gz"
    if kind == "gnu":
        bundle.write_bytes(base64.b64decode(_GNU_SPARSE))
    else:
        records = {"pax-0.0": {"GNU.sparse.size": "1", "GNU.sparse.numblocks": "0"},
                   "pax-0.1": {"GNU.sparse.size": "1", "GNU.sparse.map": "0,1"},
                   "pax-1.0": _SPARSE_10}[kind]
        _pax_sparse(bundle, records, b"1\n0\n1\n".ljust(512, b"\0"))
    with pytest.raises(BundleError) as e:
        extract_bundle(bundle, tmp_path / "incoming")
    text = str(e.value)
    assert "is a sparse file" in text and "only files, directories and links" in text
    assert "boxmunge bundle" in text


def test_a_pax_sparse_map_is_refused_before_it_is_read(tmp_path) -> None:
    """Review: a 261 KB bundle's PAX 1.0 map took 7 GB as tarfile read it."""
    import tracemalloc
    pairs = 1 << 20
    body = f"{pairs}\n".encode() + b"0\n" * (2 * pairs)
    bundle = _pax_sparse(tmp_path / "myapp.tar.gz", _SPARSE_10, body)
    tracemalloc.start()
    try:
        with pytest.raises(BundleError, match="is a sparse file"):
            extract_bundle(bundle, tmp_path / "incoming")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 2 * 1024 ** 2, peak


def _gz_bundle(path: Path, write) -> Path:
    import gzip
    with gzip.open(path, "wb") as gz:
        write(gz)
        gz.write(b"\0" * 1024)
    return path


def test_entries_are_counted_as_they_are_read_not_all_held_first(tmp_path, monkeypatch) -> None:
    """Review: getmembers() built every header (1.5M entries: 0.68 GB, 48 s)
    before the count was checked; the count now stops the read."""
    monkeypatch.setattr("boxmunge.bundle.MAX_MEMBERS", 5)
    block = tarfile.TarInfo("myapp/x").tobuf(tarfile.GNU_FORMAT)
    bundle = _gz_bundle(tmp_path / "myapp.tar.gz", lambda gz: gz.write(block * 5000))
    read = []
    real = tarfile.TarInfo.fromtarfile.__func__
    monkeypatch.setattr(tarfile.TarInfo, "fromtarfile",
                        classmethod(lambda cls, t: read.append(1) or real(cls, t)))
    with pytest.raises(BundleError, match="more than 5 entries"):
        extract_bundle(bundle, tmp_path / "incoming")
    assert len(read) <= 6


def test_a_huge_extended_header_is_refused_before_it_is_read(tmp_path) -> None:
    """Review: tarfile reads a PAX (or GNU long-name) header into memory
    whole, so a 1 MB bundle could make it allocate 1 GiB before any cap."""
    import tracemalloc
    header = tarfile.TarInfo("myapp/././@PaxHeader")
    header.type = tarfile.XHDTYPE
    header.size = 8 * 1024 ** 2

    def write(gz) -> None:
        gz.write(header.tobuf(tarfile.PAX_FORMAT))
        gz.write(b"\0" * header.size)
    bundle = _gz_bundle(tmp_path / "myapp.tar.gz", write)
    tracemalloc.start()
    try:
        with pytest.raises(BundleError, match=r"extended \(PAX or long-name\) header of 8\.0 MiB"):
            extract_bundle(bundle, tmp_path / "incoming")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 4 * 1024 ** 2, peak


def test_the_archive_may_not_run_past_what_the_limits_allow(monkeypatch) -> None:
    """The stream bounds whatever a header makes tarfile read beyond what
    the other limits count: contents, an allowance per entry, and the
    extended headers."""
    from boxmunge import bundle
    for limit, value in (("MAX_TOTAL_BYTES", 1000), ("MAX_MEMBERS", 2),
                         ("MAX_EXTENDED_TOTAL_BYTES", 0)):
        monkeypatch.setattr(bundle, limit, value)
    stream = bundle._LimitedStream(io.BytesIO(b"\0" * 4096))
    assert len(stream.read(3000)) == 3000
    with pytest.raises(BundleError, match="runs past 3048 bytes"):
        stream.read(512)
