"""Rollback order: data back before the old daemon starts; soak volumes after."""
from __future__ import annotations

import pytest

from boxmunge.userns import rollback as rb
from boxmunge.userns.inventory import Inventory, VolumeEntry
from boxmunge.userns.journal import FORWARD, ROLLBACK, Journal, load_journal, save_journal
from boxmunge.userns.preflight import Report
from tests.integration.userns.dockerd import FakeTimers

S = 1048576


def _vol(name):
    return VolumeEntry(name, "local", {}, {"com.docker.compose.volume": name}, "/m", False, False,
                       True)


class _Daemon:
    def __init__(self, events):
        self.events = events

    def stop(self):
        self.events.append("daemon stop")

    def start(self):
        self.events.append("daemon start")


@pytest.fixture
def remapped(paths, monkeypatch, tmp_path):
    old_root = tmp_path / "docker"
    (old_root / "volumes" / "old_v").mkdir(parents=True)  # its _data left with the migration
    (old_root / "volumes" / "kept_v" / "_data").mkdir(parents=True)  # never moved
    new_root = old_root / f"{S}.{S}"
    new_root.mkdir()
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    finv = Inventory("overlayfs", "io.containerd.snapshotter.v1", str(old_root), "29.9.0",
                     projects=["shop"], volumes=[_vol("old_v"), _vol("kept_v")],
                     record_data=[str(uploads)])
    rinv = Inventory("overlay2", "", str(new_root), "29.9.0", projects=["shop"],
                     volumes=[_vol("old_v"), _vol("kept_v"), _vol("soak_v")])
    save_journal(paths, Journal(FORWARD, "applied", S, daemon_json='{"x": 1}',
                                prior_store={"driver": "overlayfs",
                                             "driver_type": "io.containerd.snapshotter.v1"},
                                inventory=finv.to_json(), timers={"t": True},
                                items={"caddyfile": "0644"}, caddyfile_mode=0o640,
                                applied_at="2026-10-16T00:00:00+00:00"))
    events: list[str] = []
    monkeypatch.setattr(rb, "load_registered_projects", lambda p: {"shop"})
    monkeypatch.setattr(rb, "take_inventory", lambda p: rinv)
    monkeypatch.setattr(rb, "daemon_answers", lambda: True)
    monkeypatch.setattr(rb, "preflight", lambda *a, **kw: Report())
    monkeypatch.setattr(rb, "save_all", lambda *a, **kw: events.append("save-images"))
    monkeypatch.setattr(rb, "quiesce", lambda inv: events.append("quiesce"))
    monkeypatch.setattr(rb, "move", lambda src, dst, name: events.append(f"move {name}"))
    monkeypatch.setattr(rb, "shift_journalled", lambda j, tree, d, save, key: events.append(
        f"unshift {tree.name if tree.name != '_data' else tree.parent.name}"))
    monkeypatch.setattr(rb, "set_caddyfile_mode", lambda p, mode: events.append(f"caddyfile {mode:o}"))
    monkeypatch.setattr(rb, "back_to_prior", lambda paths, text, s, daemon: (
        events.append(f"daemon.json {text}"), daemon.stop(), daemon.start()))
    monkeypatch.setattr(rb, "_verify_prior_store", lambda j: events.append("prior store verified"))
    monkeypatch.setattr(rb, "recreate", lambda v: events.append(f"create {v.name}"))
    monkeypatch.setattr(rb, "load_all", lambda *a, **kw: events.append("load-images"))
    monkeypatch.setattr(rb, "_leftovers", lambda p, j, save: events.append("leftovers"))
    monkeypatch.setattr(rb, "bring_up", lambda *a, **kw: events.append("bring-up"))
    monkeypatch.setattr(rb, "remove_tars", lambda d: events.append("tars removed"))
    monkeypatch.setattr(rb, "notify", lambda *a, **kw: True)
    return events, new_root


def test_the_order_that_keeps_old_containers_safe(paths, remapped) -> None:
    events, new_root = remapped
    timers = FakeTimers()
    rb.rollback(paths, daemon=_Daemon(events), timers=timers)
    start = events.index("daemon start")
    for before in ("quiesce", "daemon stop", "move old_v", "unshift old_v", "unshift uploads",
                   "caddyfile 640", 'daemon.json {"x": 1}'):
        assert events.index(before) < start, before
    for after in ("prior store verified", "create soak_v", "move soak_v", "unshift soak_v",
                  "load-images", "leftovers", "bring-up", "tars removed"):
        assert events.index(after) > start, after
    assert "move kept_v" not in events and "unshift kept_v" not in events
    assert not new_root.exists()
    j = load_journal(paths)
    assert j.phase == "rolled-back" and j.items["rb-volume:kept_v"] == "stayed"
    assert timers.calls[-1][0] == "restore"


def test_resume_after_a_crash_mid_restore(paths, remapped, monkeypatch) -> None:
    events, _ = remapped
    calls = {"n": 0}

    def crash_once(j, tree, d, save, key):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("power cut")
        events.append(f"unshift {tree.name}")
    monkeypatch.setattr(rb, "shift_journalled", crash_once)
    with pytest.raises(RuntimeError, match="power cut"):
        rb.rollback(paths, daemon=_Daemon(events), timers=FakeTimers())
    j = load_journal(paths)
    assert j.phase == "rb-quiesced" and j.failed.endswith("power cut")
    events.clear()
    rb.rollback(paths, daemon=_Daemon(events), timers=FakeTimers())
    assert "quiesce" not in events and "move old_v" not in events  # done before the crash
    assert events[0] == "daemon stop"  # a reboot may have started the remapped daemon
    assert load_journal(paths).phase == "rolled-back"


def test_a_migration_stopped_before_the_switch_is_aborted(paths, monkeypatch, tmp_path) -> None:
    calls = []
    save_journal(paths, Journal(FORWARD, "quiesced", S, daemon_json=None, timers={"t": True},
                                inventory=Inventory("overlay2", "", str(tmp_path), "29").to_json()))
    monkeypatch.setattr(rb, "load_registered_projects", lambda p: set())
    monkeypatch.setattr(rb, "ensure_prior", lambda *a: calls.append("ensure-prior"))
    monkeypatch.setattr(rb, "bring_up", lambda *a, **kw: calls.append(kw["prefix"]))
    monkeypatch.setattr(rb, "remove_tars", lambda d: calls.append("tars"))
    timers = FakeTimers()
    rb.rollback(paths, daemon=_Daemon([]), timers=timers)
    assert calls == ["ensure-prior", "abort", "tars"] and load_journal(paths).phase == "rolled-back"
    assert timers.calls == [("restore", '{"t": true}')]


def test_an_abort_before_any_stop_starts_nothing(paths, monkeypatch, tmp_path) -> None:
    save_journal(paths, Journal(FORWARD, "started", S,
                                inventory=Inventory("overlay2", "", str(tmp_path), "29").to_json()))
    monkeypatch.setattr(rb, "load_registered_projects", lambda p: set())
    monkeypatch.setattr(rb, "ensure_prior", lambda *a: None)
    monkeypatch.setattr(rb, "bring_up", lambda *a, **kw: pytest.fail("brought up"))
    monkeypatch.setattr(rb, "remove_tars", lambda d: None)
    assert rb.rollback(paths, daemon=_Daemon([]), timers=FakeTimers()).phase == "rolled-back"


@pytest.mark.parametrize("journal, match", [
    (None, "no userns migration"),
    (Journal(FORWARD, "committed", S), "committed"),
    (Journal(ROLLBACK, "rolled-back", S), "already rolled back"),
])
def test_refusals(paths, journal, match) -> None:
    if journal is not None:
        save_journal(paths, journal)
    with pytest.raises(rb.MigrationError, match=match):
        rb.rollback(paths, daemon=_Daemon([]), timers=FakeTimers())


def test_where_each_volume_goes_back(tmp_path) -> None:
    (tmp_path / "volumes" / "moved").mkdir(parents=True)
    (tmp_path / "volumes" / "kept" / "_data").mkdir(parents=True)
    assert [rb._where(tmp_path, n) for n in ("moved", "kept", "new")] == ["old", "stayed", "soak"]
