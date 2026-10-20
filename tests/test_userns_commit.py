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


@pytest.fixture(autouse=True)
def alerts(monkeypatch):
    sent = []
    monkeypatch.setattr(cm, "notify", lambda p, title, body, **kw: sent.append(
        (title, kw["priority"])) or True)
    return sent


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


PRIOR = {"containerd_address": "/run/containerd/containerd.sock", "namespace": "moby"}


class FakeNamespace:
    """The old daemon's namespace as ctr sees it. Its snapshots have stale
    children (as every image a container was removed from has), so removing
    one by name fails; the garbage collector, which ignores that, drops
    everything nothing roots once a synchronous collection runs."""

    def __init__(self, leases=("c1", "buildkit/x"), images=("docker.io/library/x:1",),
                 containers=(), pinned=False) -> None:
        self.leases, self.images, self.containers = set(leases), set(images), set(containers)
        self.snapshots, self.content = {"top", "base"}, {"sha256:a", "sha256:b"}
        self.pinned = pinned  # something outside the old daemon's roots holds them
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, prior, *args):
        assert prior is PRIOR
        self.calls.append(args)
        kind = args[0]
        verb = args[3] if kind == "snapshots" else args[1]
        if (kind, verb) == ("snapshots", "rm"):
            raise cm.MigrationError("cannot remove snapshot with child: failed precondition")
        if (kind, verb) == ("leases", "create"):
            self.leases.add(args[-1])
        elif (kind, verb) == ("leases", "rm"):
            self.leases -= set(a for a in args[2:] if a != "--sync")
            if "--sync" in args and not (self.leases or self.images or self.containers
                                         or self.pinned):
                self.snapshots, self.content = set(), set()
        elif (kind, verb) == ("images", "rm"):
            self.images -= set(args[2:])
        elif kind == "snapshots":
            return "KEY PARENT KIND\n" + "".join(f"{k}  Committed\n" for k in sorted(self.snapshots))
        else:
            held = {"leases": self.leases, "images": self.images, "containers": self.containers,
                    "content": self.content}[kind]
            return "".join(f"{x}\n" for x in sorted(held))
        return ""


def test_the_old_namespace_is_emptied_by_garbage_collection(monkeypatch) -> None:
    ns = FakeNamespace()
    monkeypatch.setattr(cm, "_ctr", ns)
    cm._clean_containerd(PRIOR)
    assert not (ns.leases or ns.images or ns.snapshots or ns.content)
    removals = [c for c in ns.calls if "rm" in c]
    assert removals == [("leases", "rm", "buildkit/x"), ("leases", "rm", "c1"),
                        ("images", "rm", "docker.io/library/x:1"),
                        ("leases", "rm", "--sync", cm._GC_LEASE)]  # no snapshot by name


def test_a_resumed_clean_with_nothing_left_to_remove_still_collects(monkeypatch) -> None:
    """Killed after the images went but before containerd collected them."""
    ns = FakeNamespace(leases=(), images=())
    monkeypatch.setattr(cm, "_ctr", ns)
    cm._clean_containerd(PRIOR)
    assert not (ns.snapshots or ns.content)
    assert ("leases", "rm", "--sync", cm._GC_LEASE) in ns.calls


@pytest.mark.parametrize("kw, held", [
    ({"containers": ("old",)}, "1 containers, 2 content blobs, 2 snapshots"),
    ({"pinned": True}, "2 content blobs, 2 snapshots"),
])
def test_what_the_collector_leaves_is_loud(monkeypatch, kw, held) -> None:
    monkeypatch.setattr(cm, "_ctr", FakeNamespace(**kw))
    with pytest.raises(cm.MigrationError, match=f"namespace moby still holds {held} after"
                       r".*ctr --address /run/containerd/containerd.sock -n moby containers ls"
                       r".*run userns-commit again"):
        cm._clean_containerd(PRIOR)


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


def test_data_the_migration_did_not_carry_stops_the_commit(paths, tmp_path, remapped) -> None:
    left = tmp_path / "volumes" / ("a" * 64) / "_data"
    left.mkdir(parents=True)
    (left / "row").write_text("42")
    (tmp_path / "volumes" / "moved").mkdir()  # its _data left with the migration
    _journal(paths, tmp_path, {"driver_type": "", "store_root": str(tmp_path / "overlay2"),
                               "size": 0})
    with pytest.raises(cm.MigrationError, match="still hold data the migration did not carry"):
        cm.commit(paths, now=SOAKED, images_dir=tmp_path / "img")
    assert (left / "row").exists() and load_journal(paths).phase == "applied"


def test_a_commit_alerts_how_it_went(paths, tmp_path, remapped, alerts) -> None:
    _journal(paths, tmp_path, {"driver_type": "", "store_root": str(tmp_path / "overlay2"),
                               "size": 0})
    with pytest.raises(cm.MigrationError, match="soak until"):
        cm.commit(paths, now=APPLIED)
    assert alerts == []  # the operator committed early: a refusal, not a failure
    cm.commit(paths, now=SOAKED, images_dir=tmp_path / "img")
    assert alerts == [("userns migration committed", 0)]


def test_a_failure_once_the_commit_began_alerts(paths, tmp_path, monkeypatch, remapped,
                                                alerts) -> None:
    monkeypatch.setattr(cm, "_GC_WAIT", 0)
    _journal(paths, tmp_path, {"driver_type": cm.CONTAINERD_STORE, "store_root": str(tmp_path),
                               "containerd_address": "/run/x.sock", "namespace": "moby",
                               "managed": False, "size": 10**9})
    monkeypatch.setattr(cm, "_clean_containerd", lambda prior: None)
    with pytest.raises(cm.MigrationError, match="only 0 bytes were freed"):
        cm.commit(paths, now=SOAKED, images_dir=tmp_path / "img")
    assert alerts == [("userns commit stopped", 1)]


@pytest.mark.parametrize("journal", [None, Journal(FORWARD, "rebuilt", S)])
def test_nothing_to_commit_sends_no_alert(paths, journal, alerts) -> None:
    if journal is not None:
        save_journal(paths, journal)
    with pytest.raises(cm.MigrationError, match="nothing to commit"):
        cm.commit(paths, now=SOAKED)
    assert alerts == []
