"""Volumes carried verbatim; a move resumes after a crash (Review Focus 4, 5)."""
from __future__ import annotations

import os

import pytest

from boxmunge.userns import volumes as vol
from boxmunge.userns.inventory import VolumeEntry
from boxmunge.userns.volumes import VolumeError, data_dir, move, recreate

LABELS = {"com.docker.compose.project": "shop", "com.docker.compose.volume": "data",
          "note": "a=b,c", "ünïcode": "välue"}


def _entry(name="shop_data.v1", labels=LABELS, **kw):
    return VolumeEntry(name, kw.get("driver", "local"), kw.get("options", {}), dict(labels),
                       "/x", True, False, True)


def test_recreate_verifies_labels_verbatim(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(vol, "_run", lambda cmd, capture=False: calls.append(cmd))
    monkeypatch.setattr(vol, "volume_labels", lambda name: dict(LABELS))
    recreate(_entry())
    assert "--label" in calls[0] and "note=a=b,c" in calls[0] and calls[0][-1] == "shop_data.v1"
    monkeypatch.setattr(vol, "volume_labels", lambda name: {"other": "1"})
    with pytest.raises(VolumeError, match="returns an existing volume"):
        recreate(_entry())


def test_null_labels_round_trip(monkeypatch) -> None:
    monkeypatch.setattr(vol, "_run", lambda cmd, capture=False: None)
    monkeypatch.setattr(vol, "volume_labels", lambda name: {})
    recreate(_entry(labels={}))


@pytest.mark.parametrize("kw", [{"driver": "nfs"}, {"options": {"type": "tmpfs"}}])
def test_only_plain_local_volumes_are_recreated(monkeypatch, kw) -> None:
    monkeypatch.setattr(vol, "_run", lambda cmd, capture=False: pytest.fail("ran"))
    with pytest.raises(VolumeError, match="only plain local"):
        recreate(_entry(**kw))


def _roots(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    data_dir(old, "v").mkdir(parents=True)
    (data_dir(old, "v") / "row").write_text("42")
    data_dir(new, "v").mkdir(parents=True)  # Docker's fresh empty _data
    return old, new


def test_move_replaces_dockers_empty_data(tmp_path) -> None:
    old, new = _roots(tmp_path)
    move(old, new, "v")
    assert (data_dir(new, "v") / "row").read_text() == "42"
    assert not data_dir(old, "v").exists()


def test_move_resumes_after_rename_before_journal(tmp_path) -> None:
    old, new = _roots(tmp_path)
    move(old, new, "v")
    move(old, new, "v")  # the crash came before the journal said "moved"
    assert (data_dir(new, "v") / "row").read_text() == "42"


def test_move_back_into_a_root_whose_data_left(tmp_path) -> None:
    """Rollback: the old root kept the volume's directory, not its _data."""
    old, new = _roots(tmp_path)
    move(old, new, "v")
    move(new, old, "v")
    assert (data_dir(old, "v") / "row").read_text() == "42"


def test_move_refuses_a_destination_that_holds_data(tmp_path) -> None:
    old, new = _roots(tmp_path)
    (data_dir(new, "v") / "stray").write_text("x")
    with pytest.raises(VolumeError, match="not the empty directory"):
        move(old, new, "v")


def test_move_refuses_links(tmp_path) -> None:
    old, new = _roots(tmp_path)
    data_dir(new, "v").rmdir()
    os.symlink(tmp_path, data_dir(new, "v"))
    with pytest.raises(VolumeError, match="not the empty directory"):
        move(old, new, "v")


def test_a_volume_missing_on_both_sides_is_loud(tmp_path) -> None:
    with pytest.raises(VolumeError, match="neither"):
        move(tmp_path / "old", tmp_path / "new", "v")
