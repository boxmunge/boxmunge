"""One tar per image; resumable; every tag must resolve after the load."""
from __future__ import annotations

import pytest

from boxmunge.userns import images as im
from boxmunge.userns import layers
from boxmunge.userns.inventory import ImageEntry
from boxmunge.userns.journal import FORWARD, Journal
from tests.test_userns_layers import _layer, _save

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
    monkeypatch.setattr(im, "_run", lambda cmd, capture=False, timeout=None:
                        type("R", (), {"stdout": ""})())
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


DIGEST_ONLY = ImageEntry("sha256:" + "c" * 64, [], 7, True,
                         refs=["busybox:1.36@sha256:" + "d" * 64])


def test_a_digest_only_image_is_saved_by_id_and_pulled_by_its_digest(tmp_path, monkeypatch) -> None:
    calls = []

    def run(cmd, capture=False, timeout=None):
        calls.append(cmd[:3])
        if cmd[:2] == ["docker", "save"]:
            open(cmd[3], "w").write("tar")
        out = "Loaded image ID: sha256:new\n" if cmd[:2] == ["docker", "load"] else ""
        return type("R", (), {"stdout": out})()
    monkeypatch.setattr(im, "_run", run)
    pulled = set()
    monkeypatch.setattr(im, "_resolves", lambda ref: ref in pulled)
    j = Journal(FORWARD, "started", S)
    im.save_all([DIGEST_ONLY], j, tmp_path / "b" / "img", lambda: None)
    assert calls == [["docker", "save", "-o"]]

    def pull(cmd, capture=False, timeout=None):
        r = run(cmd)
        if cmd[:2] == ["docker", "pull"]:
            pulled.add(cmd[3])
        return r
    monkeypatch.setattr(im, "_run", pull)
    im.load_all([DIGEST_ONLY], j, tmp_path / "b" / "img", lambda: None)
    assert j.image_map == {DIGEST_ONLY.id: "sha256:new"}
    assert j.items[f"image-ref:{DIGEST_ONLY.refs[0]}"] == "pulled"
    calls.clear()
    im.load_all([DIGEST_ONLY], j, tmp_path / "b" / "img", lambda: None)
    assert calls == []  # loaded and pulled: nothing again


def test_a_failed_digest_pull_says_what_to_do(tmp_path, monkeypatch) -> None:
    def run(cmd, capture=False, timeout=None):
        if cmd[:2] == ["docker", "pull"]:
            raise im.DockerError("registry unreachable")
        return type("R", (), {"stdout": "Loaded image ID: sha256:new\n"})()
    monkeypatch.setattr(im, "_run", run)
    monkeypatch.setattr(im, "_resolves", lambda ref: False)
    j = Journal(FORWARD, "switched", S, items={f"image:{DIGEST_ONLY.id}": "saved"})
    with pytest.raises(im.ImageError, match="once the registry answers, run the same command"):
        im.load_all([DIGEST_ONLY], j, tmp_path, lambda: None)
    assert j.items[f"image:{DIGEST_ONLY.id}"] == "loaded"  # the load is not redone


def test_an_untagged_unreferenced_image_is_not_carried(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(im, "_run", lambda *a, **kw: pytest.fail("ran"))
    loose = ImageEntry("sha256:" + "e" * 64, [], 1, False)
    im.save_all([loose], Journal(FORWARD, "started", S), tmp_path / "b" / "img", lambda: None)
    im.load_all([loose], Journal(FORWARD, "switched", S), tmp_path, lambda: None)


def _tagged(n: int, tag: str) -> ImageEntry:
    return ImageEntry("sha256:" + str(n) * 64, [tag], 1, True)


def _saver(monkeypatch, tars: dict[str, bytes]) -> list[list[str]]:
    """`docker save -o <tar> <tag>` writes that tag's bytes; nothing else runs."""
    calls: list[list[str]] = []

    def run(cmd, capture=False, timeout=None):
        assert cmd[:3] == ["docker", "save", "-o"], cmd
        calls.append(cmd)
        open(cmd[3], "wb").write(tars[cmd[4]])
    monkeypatch.setattr(im, "_run", run)
    monkeypatch.setattr(layers.subprocess, "Popen",
                        lambda *a, **kw: pytest.fail("saved an image a second time"))
    return calls


def test_high_ids_are_read_from_the_tar_just_saved_and_every_offender_named(
        tmp_path, monkeypatch) -> None:
    """The forward migration's check: no second `docker save`. A refused
    image leaves no tar and no journal entry; the others are saved, so one
    run names every offender and a rerun saves only what was replaced."""
    clean = _save(("blobs/sha256/a", _layer(0))).getvalue()
    high = _save(("blobs/sha256/b", _layer(70000))).getvalue()
    zstd = _save(("blobs/sha256/z", b"\x28\xb5\x2f\xfd" + b"\0" * 600)).getvalue()
    images = [_tagged(1, "bad:1"), _tagged(2, "good:1"), _tagged(3, "packed:1"),
              _tagged(4, "fine:1")]
    calls = _saver(monkeypatch, {"bad:1": high, "good:1": clean, "packed:1": zstd,
                                 "fine:1": clean})
    j = Journal(FORWARD, "started", S)
    directory = tmp_path / "b" / "img"
    with pytest.raises(im.ImageError) as refused:
        im.save_all(images, j, directory, lambda: None, refuse_high_ids=True)
    assert str(refused.value) == (
        "image bad:1 has files owned by ids above 65535 (etc/f (70000:70000)), which a "
        "remapped daemon cannot load. Rebuild or replace it and redeploy; "
        "image packed:1: blobs/sha256/z is a zstd-compressed layer, which boxmunge cannot read")
    assert j.items == {f"image:{images[1].id}": "saved", f"image:{images[3].id}": "saved"}
    assert sorted(f.name for f in directory.iterdir()) == [f"{'2' * 64}.tar", f"{'4' * 64}.tar"]
    assert len(calls) == 4  # one save each
    calls.clear()
    with pytest.raises(im.ImageError):
        im.save_all(images, j, directory, lambda: None, refuse_high_ids=True)
    assert [c[4] for c in calls] == ["bad:1", "packed:1"]  # the saved ones are kept


def test_a_rollback_s_save_reads_no_tar(tmp_path, monkeypatch) -> None:
    """The unremapped daemon it goes back to loads any id."""
    high = _save(("blobs/sha256/b", _layer(70000))).getvalue()
    _saver(monkeypatch, {"bad:1": high})
    monkeypatch.setattr(im, "high_ids", lambda stream: pytest.fail("read the tar"))
    j = Journal(FORWARD, "applied", S)
    im.save_all([_tagged(1, "bad:1")], j, tmp_path / "b" / "img", lambda: None,
                prefix="rb-image")
    assert j.items == {f"rb-image:{'sha256:' + '1' * 64}": "saved"}
