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
    with patch("boxmunge.commands.deploy.compose_up") as up:
        rc = run_deploy("myapp", paths)
    assert rc == 1
    up.assert_not_called()
    err = capsys.readouterr().err
    assert err.startswith("ERROR:")
    assert "myapp/link" in err
    assert not paths.project_dir("myapp").exists()
