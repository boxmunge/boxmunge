"""Commit: only after the soak, only healthy, per prior store, verified."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.userns import commit as cm
from boxmunge.userns.inventory import Inventory
from boxmunge.userns.journal import FORWARD, Journal, load_journal, save_journal

S = 1048576
APPLIED = datetime(2026, 10, 16, tzinfo=timezone.utc)
SOAKED = APPLIED + timedelta(hours=49)


def _journal(paths, root, prior):
    save_journal(paths, Journal(FORWARD, "applied", S, prior_store=prior,
                                inventory=Inventory("x", "", str(root), "29").to_json(),
                                applied_at=APPLIED.isoformat()))


@pytest.fixture
def remapped(monkeypatch):
    monkeypatch.setattr(cm.uo, "remap_offset", lambda paths: S)
    monkeypatch.setattr(cm, "deployed_among", lambda names, paths: [])


def test_refuses_inside_the_soak_and_when_unhealthy(paths, tmp_path, monkeypatch, remapped) -> None:
    _journal(paths, tmp_path, {"driver_type": "", "store_root": str(tmp_path / "overlay2"), "size": 0})
    with pytest.raises(cm.MigrationError, match="soak until"):
        cm.commit(paths, now=APPLIED + timedelta(hours=47))
    monkeypatch.setattr(cm, "deployed_among", lambda names, paths: ["shop"])
    monkeypatch.setattr(cm, "run_check", lambda p, paths, verbose: 2)
    with pytest.raises(cm.MigrationError, match="not every project is healthy: shop"):
        cm.commit(paths, now=SOAKED)


def test_refuses_when_the_daemon_is_not_the_journalled_one(paths, tmp_path, monkeypatch) -> None:
    _journal(paths, tmp_path, {"driver_type": "", "store_root": str(tmp_path), "size": 0})
    monkeypatch.setattr(cm.uo, "remap_offset", lambda paths: 0)
    with pytest.raises(cm.MigrationError, match="not remapped as the journal says"):
        cm.commit(paths, now=SOAKED)


@pytest.mark.parametrize("journal", [None, Journal(FORWARD, "rebuilt", S),
                                     Journal(FORWARD, "committed", S)])
def test_nothing_to_commit(paths, journal) -> None:
    if journal is not None:
        save_journal(paths, journal)
    with pytest.raises(cm.MigrationError, match="nothing to commit"):
        cm.commit(paths, now=SOAKED)


def test_graph_driver_store_is_removed_and_verified(paths, tmp_path, monkeypatch, remapped) -> None:
    (tmp_path / "overlay2" / "layer").mkdir(parents=True)
    (tmp_path / "overlay2" / "layer" / "f").write_bytes(b"x" * 100000)
    for sub in ("containers", "volumes", "image"):
        (tmp_path / sub).mkdir()
    (tmp_path / f"{S}.{S}").mkdir()  # the remapped root stays
    size = cm._old_store_size({"driver_type": ""}, tmp_path)
    _journal(paths, tmp_path, {"driver_type": "", "store_root": str(tmp_path / "overlay2"),
                               "size": size})
    cm.commit(paths, now=SOAKED, images_dir=tmp_path / "img")
    assert not (tmp_path / "overlay2").exists() and (tmp_path / f"{S}.{S}").exists()
    assert not (tmp_path / "volumes").exists()
    j = load_journal(paths)
    assert j.phase == "committed" and int(j.items["commit-before"]) == size


def test_a_commit_resumed_after_a_crash_measures_against_the_first_size(
        paths, tmp_path, monkeypatch, remapped) -> None:
    (tmp_path / "overlay2").mkdir()
    _journal(paths, tmp_path, {"driver_type": "", "store_root": str(tmp_path / "overlay2"),
                               "size": 100000})
    j = load_journal(paths)
    j.items["commit-before"] = "100000"  # the first run deleted the layers, then died
    save_journal(paths, j)
    assert cm.commit(paths, now=SOAKED, images_dir=tmp_path / "img").phase == "committed"


def test_a_store_that_did_not_shrink_is_loud(paths, tmp_path, monkeypatch, remapped) -> None:
    monkeypatch.setattr(cm, "_GC_WAIT", 0)
    _journal(paths, tmp_path, {"driver_type": cm.CONTAINERD_STORE, "store_root": str(tmp_path),
                               "containerd_address": "/run/x.sock", "namespace": "moby",
                               "managed": False, "size": 10**9})
    monkeypatch.setattr(cm, "_clean_containerd", lambda prior: None)
    with pytest.raises(cm.MigrationError, match="only 0 bytes were freed"):
        cm.commit(paths, now=SOAKED, images_dir=tmp_path / "img")
    assert load_journal(paths).phase == "applied"


def test_snapshots_go_children_first() -> None:
    listing = ("KEY PARENT KIND\n"
               "base  Committed\n"
               "mid base Committed\n"
               "c1-init mid Active\n"
               "c1 c1-init Active\n")
    assert cm.snapshot_removal_order(listing) == ["c1", "c1-init", "mid", "base"]


def test_containerd_cleanup_order(monkeypatch) -> None:
    calls = []

    def ctr(prior, *args):
        calls.append(args[:2])
        return {("leases", "ls"): "l1\n", ("snapshots", "--snapshotter"): "KEY PARENT KIND\ns1  Active\n",
                ("images", "ls"): "docker.io/library/x:1\n"}.get(args[:2], "")
    monkeypatch.setattr(cm, "_ctr", ctr)
    cm._clean_containerd({"containerd_address": "/run/containerd/containerd.sock", "namespace": "moby"})
    kinds = [c[0] for c in calls]
    assert kinds.index("leases") < kinds.index("snapshots") < kinds.index("images")


def test_dockerds_own_old_containerd_root_is_removed(paths, tmp_path, remapped) -> None:
    store = tmp_path / "containerd" / "daemon"
    (store / "io.containerd.content.v1.content").mkdir(parents=True)
    (store / "io.containerd.content.v1.content" / "blob").write_bytes(b"x" * 100000)
    (tmp_path / f"{S}.{S}" / "containerd" / "daemon").mkdir(parents=True)
    prior = {"driver_type": cm.CONTAINERD_STORE, "store_root": str(store), "managed": True,
             "containerd_address": "/var/run/docker/containerd/containerd.sock",
             "namespace": "moby", "size": cm._old_store_size(
                 {"driver_type": cm.CONTAINERD_STORE, "store_root": str(store)}, tmp_path)}
    _journal(paths, tmp_path, prior)
    assert cm.commit(paths, now=SOAKED, images_dir=tmp_path / "img").phase == "committed"
    assert not store.exists() and (tmp_path / f"{S}.{S}" / "containerd" / "daemon").is_dir()


def test_an_old_containerd_root_still_in_use_is_left(paths, tmp_path, remapped) -> None:
    store = tmp_path / "containerd" / "daemon"
    store.mkdir(parents=True)
    _journal(paths, tmp_path, {"driver_type": cm.CONTAINERD_STORE, "store_root": str(store),
                               "managed": True, "size": 0})
    with pytest.raises(cm.MigrationError, match="may still be in use"):
        cm.commit(paths, now=SOAKED, images_dir=tmp_path / "img")
    assert store.is_dir()


def test_a_missing_store_measures_nothing(tmp_path) -> None:
    from boxmunge.userns.preflight_checks import dir_size
    assert dir_size(tmp_path / "gone") == 0
    (tmp_path / "f").write_bytes(b"x" * 10000)
    assert dir_size(tmp_path) >= 10000
