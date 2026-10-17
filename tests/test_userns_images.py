"""One tar per image; resumable; every tag must resolve after the load."""
from __future__ import annotations

import pytest

from boxmunge.userns import images as im
from boxmunge.userns.inventory import ImageEntry
from boxmunge.userns.journal import FORWARD, Journal

S = 1048576
IMAGES = [ImageEntry("sha256:" + "a" * 64, ["postgres:16", "postgres:latest"], 10, True),
          ImageEntry("sha256:" + "b" * 64, [], 5, True)]


def test_save_one_tar_per_tagged_image_and_resume(tmp_path, monkeypatch) -> None:
    calls = []

    def run(cmd, capture=False, timeout=None):
        calls.append(cmd)
        if cmd[:2] == ["docker", "save"]:
            open(cmd[3], "w").write("tar")
    monkeypatch.setattr(im, "_run", run)
    j = Journal(FORWARD, "started", S)
    saves = []
    im.save_all(IMAGES, j, tmp_path / "base" / "img", lambda: saves.append(dict(j.items)))
    assert [c[4:] for c in calls] == [["postgres:16", "postgres:latest"]]  # one save, both tags
    assert im.tar_path(tmp_path / "base" / "img", IMAGES[0].id).read_text() == "tar"
    assert not list((tmp_path / "base" / "img").glob("*.partial"))
    assert saves == [{f"image:{IMAGES[0].id}": "saved"}]
    assert oct((tmp_path / "base").stat().st_mode & 0o777) == "0o700"
    im.save_all(IMAGES, j, tmp_path / "base" / "img", lambda: None)
    assert len(calls) == 1  # journalled: not saved again


def test_a_partial_tar_from_a_crash_is_written_again(tmp_path, monkeypatch) -> None:
    def run(cmd, capture=False, timeout=None):
        open(cmd[3], "w").write("whole")
    monkeypatch.setattr(im, "_run", run)
    directory = tmp_path / "b" / "img"
    im.ensure_dir(directory)
    im.tar_path(directory, IMAGES[0].id).with_suffix(".partial").write_text("half")
    im.save_all(IMAGES, Journal(FORWARD, "started", S), directory, lambda: None)
    assert im.tar_path(directory, IMAGES[0].id).read_text() == "whole"


def test_load_maps_old_to_new_and_needs_every_tag(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(im, "_run", lambda cmd, capture=False, timeout=None: None)
    monkeypatch.setattr(im, "image_id", lambda tag: "sha256:new")
    saved = {f"image:{IMAGES[0].id}": "saved"}
    j = Journal(FORWARD, "switched", S, items=dict(saved))
    im.load_all(IMAGES, j, tmp_path, lambda: None)
    assert j.image_map == {IMAGES[0].id: "sha256:new"}
    monkeypatch.setattr(im, "image_id", lambda tag: f"sha256:{tag}")
    with pytest.raises(im.ImageError, match="name different images"):
        im.load_all(IMAGES, Journal(FORWARD, "switched", S, items=dict(saved)), tmp_path,
                    lambda: None)


def test_an_image_never_saved_is_not_loaded(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(im, "_run", lambda *a, **kw: pytest.fail("loaded"))
    with pytest.raises(im.ImageError, match="never saved"):
        im.load_all(IMAGES, Journal(FORWARD, "switched", S), tmp_path, lambda: None)


def test_a_shared_tar_directory_is_refused(tmp_path) -> None:
    (tmp_path / "b").mkdir(mode=0o755)
    with pytest.raises(im.ImageError, match="mode 0700"):
        im.ensure_dir(tmp_path / "b" / "img")
