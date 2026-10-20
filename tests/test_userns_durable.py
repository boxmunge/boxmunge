"""The barrier before a journal save: every filesystem the journal depends on, flushed."""
from __future__ import annotations

import sys

import pytest

from boxmunge.userns import durable
from boxmunge.userns.journal import FORWARD, Journal

S = 1048576


@pytest.fixture
def roots(monkeypatch, tmp_path):
    docker, containerd = tmp_path / "docker", tmp_path / "containerd"
    (docker / f"{S}.{S}").mkdir(parents=True)
    monkeypatch.setattr(durable, "DEFAULT_DATA_ROOT", str(docker))
    monkeypatch.setattr(durable, "SYSTEM_CONTAINERD_ROOT", str(containerd))  # absent
    return docker, containerd


def _journal(**prior) -> Journal:
    return Journal(FORWARD, "switched", S, prior_store=prior)


def test_one_flush_per_filesystem_and_none_for_what_is_absent(paths, roots, monkeypatch,
                                                              tmp_path) -> None:
    docker, _ = roots
    images = tmp_path / "images"
    images.mkdir()
    devs = {str(docker / f"{S}.{S}"): -2, str(images): -3}  # each a filesystem of its own
    real = durable._device
    monkeypatch.setattr(durable, "_device", lambda p: devs.get(str(p), real(p)))
    flushed = []
    monkeypatch.setattr(durable, "syncfs", flushed.append)
    durable.barrier(paths, _journal(store_root=str(tmp_path / "gone")), images)
    assert flushed == [paths.root, docker / f"{S}.{S}", images]  # docker shares the box's


def test_a_flush_that_fails_stops_the_save(paths, roots, monkeypatch) -> None:
    def syncfs(path):
        raise OSError(5, "Input/output error")
    monkeypatch.setattr(durable, "syncfs", syncfs)
    with pytest.raises(durable.NotDurable, match=r"before journalling switched: .*Input/output"
                                                 r".*run the same command again"):
        durable.barrier(paths, _journal(), paths.root / "images")


@pytest.mark.skipif(sys.platform != "linux", reason="syncfs(2) is Linux's")
def test_syncfs_flushes_a_real_filesystem(tmp_path) -> None:
    durable.syncfs(tmp_path)
    with pytest.raises(FileNotFoundError):
        durable.syncfs(tmp_path / "gone")
