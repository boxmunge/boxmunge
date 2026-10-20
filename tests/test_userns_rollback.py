"""Rollback order: data back before the old daemon starts; soak volumes after."""
from __future__ import annotations

import pytest

from boxmunge.compose import ComposeError
from boxmunge.system_container import SystemContainerError
from boxmunge.userns import rollback as rb
from boxmunge.userns.inventory import Inventory, VolumeEntry
from boxmunge.userns.journal import FORWARD, ROLLBACK, Journal, load_journal, save_journal
from boxmunge.userns.preflight import Report
from tests.integration.userns.dockerd import FakeTimers

S = 1048576
_REFUSE_SOAK_EDIT = rb._refuse_soak_edit  # before the fixture stands it in


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
    monkeypatch.setattr(rb, "_remove_remapped_containers", lambda: events.append("rm containers"))
    monkeypatch.setattr(rb.uo, "remap_offset", lambda paths: S)
    monkeypatch.setattr(rb, "move", lambda src, dst, name: events.append(f"move {name}"))
    monkeypatch.setattr(rb, "shift_journalled", lambda j, tree, d, save, key, seed=None: events.append(
        f"unshift {tree.name if tree.name != '_data' else tree.parent.name}"))
    monkeypatch.setattr(rb, "set_caddyfile_mode", lambda p, mode: events.append(f"caddyfile {mode:o}"))
    monkeypatch.setattr(rb, "back_to_prior", lambda paths, text, s, daemon, owner=None: (
        events.append(f"daemon.json {text}"), daemon.stop(), daemon.start()))
    monkeypatch.setattr(rb, "_verify_prior_store", lambda j: events.append("prior store verified"))
    monkeypatch.setattr(rb, "recreate", lambda v: events.append(f"create {v.name}"))
    monkeypatch.setattr(rb, "load_all", lambda *a, **kw: events.append("load-images"))
    monkeypatch.setattr(rb, "_leftovers", lambda p, j, save: events.append("leftovers"))
    monkeypatch.setattr(rb, "bring_up", lambda *a, **kw: events.append("bring-up"))
    monkeypatch.setattr(rb, "remove_tars", lambda d: events.append("tars removed"))
    monkeypatch.setattr(rb, "notify", lambda *a, **kw: True)
    monkeypatch.setattr(rb, "_refuse_soak_edit", lambda j: None)
    monkeypatch.setattr(rb, "report_back", lambda paths, j, prefix, title, c: events.append(
        f"report {prefix}"))
    return events, new_root


def test_the_order_that_keeps_old_containers_safe(paths, remapped) -> None:
    events, new_root = remapped
    timers = FakeTimers()
    rb.rollback(paths, daemon=_Daemon(events), timers=timers)
    start = events.index("daemon start")
    assert events.index("quiesce") < events.index("rm containers") < events.index("daemon stop")
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

    def crash_once(j, tree, d, save, key, seed=None):
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
    monkeypatch.setattr(rb, "ensure_prior", lambda *a: calls.append("ensure-prior"))  # -> None
    monkeypatch.setattr(rb, "bring_up", lambda *a, **kw: calls.append(kw["prefix"]))
    monkeypatch.setattr(rb, "remove_tars", lambda d: calls.append("tars"))
    timers = FakeTimers()
    rb.rollback(paths, daemon=_Daemon([]), timers=timers)
    assert calls == ["ensure-prior", "abort", "tars"] and load_journal(paths).phase == "rolled-back"
    assert timers.calls == [("restore", '{"t": true}')]


def test_an_abort_from_started_still_brings_up_what_is_not_running(paths, monkeypatch,
                                                                  tmp_path) -> None:
    """An undone switch journals `started`, but a project whose restart failed during
    the undo is still down: the abort starts every project that should be running."""
    save_journal(paths, Journal(FORWARD, "started", S,
                                inventory=Inventory("overlay2", "", str(tmp_path), "29").to_json()))
    calls = []
    monkeypatch.setattr(rb, "load_registered_projects", lambda p: set())
    monkeypatch.setattr(rb, "ensure_prior", lambda *a: None)
    monkeypatch.setattr(rb, "bring_up", lambda *a, **kw: calls.append(
        (kw["prefix"], kw["only_stopped"])))
    monkeypatch.setattr(rb, "remove_tars", lambda d: None)
    assert rb.rollback(paths, daemon=_Daemon([]), timers=FakeTimers()).phase == "rolled-back"
    # The box ran on since the inventory: only what is not running now is started.
    assert calls == [("abort", True)]


def _alerts(monkeypatch):
    sent = []
    monkeypatch.setattr(rb, "notify", lambda p, title, body, **kw: sent.append(
        (title, body, kw["priority"])) or True)
    return sent


def test_timers_are_disabled_only_after_the_image_save_and_the_marker(paths, remapped,
                                                                      monkeypatch) -> None:
    """stop_all is a persistent `disable --now`: before the marker says why, a kill
    during the (long) image save would leave the box running with no timers."""
    events, _ = remapped

    class Timers(FakeTimers):
        def stop_all(self):
            events.append(f"timers stopped, marker {rb.migration_in_progress(paths)}")

    rb.rollback(paths, daemon=_Daemon(events), timers=Timers())
    assert events.index("save-images") < events.index(
        "timers stopped, marker userns-rollback") < events.index("quiesce")


def test_a_failed_image_save_leaves_the_timers_and_sets_no_marker(paths, remapped,
                                                                  monkeypatch) -> None:
    events, _ = remapped
    sent = _alerts(monkeypatch)

    def fail(*a, **kw):
        raise rb.MigrationError("no space left")
    monkeypatch.setattr(rb, "save_all", fail)
    timers = FakeTimers()
    with pytest.raises(rb.MigrationError, match="no space left"):
        rb.rollback(paths, daemon=_Daemon(events), timers=timers)
    assert timers.calls == [] and rb.migration_in_progress(paths) is None
    assert load_journal(paths).failed.endswith("no space left")
    (title, body, priority), = sent
    assert title == "userns rollback stopped" and priority == 1
    assert "marker is set" not in body and "re-run userns-rollback" in body


def _abort_box(paths, monkeypatch, tmp_path):
    from boxmunge.userns.marker import set_marker
    save_journal(paths, Journal(FORWARD, "quiesced", S, timers={"t": True},
                                inventory=Inventory("overlay2", "", str(tmp_path), "29").to_json()))
    set_marker(paths, "userns-migrate (to resume) or userns-rollback")
    monkeypatch.setattr(rb, "load_registered_projects", lambda p: set())
    monkeypatch.setattr(rb, "ensure_prior", lambda *a: None)
    monkeypatch.setattr(rb, "remove_tars", lambda d: None)
    return _alerts(monkeypatch)


def _bring_up_fails(error):
    def fail(*a, **kw):
        raise error
    return fail


@pytest.mark.parametrize("where, error", [
    ("ensure_prior", rb.MigrationError("dockerd would not start")),
    ("bring_up", SystemContainerError("the system container is down")),
    ("compose_up_platform", ComposeError("caddy would not start")),
])
def test_an_abort_that_fails_is_journalled_and_alerted(paths, monkeypatch, tmp_path, where,
                                                       error) -> None:
    sent = _abort_box(paths, monkeypatch, tmp_path)
    if where == "compose_up_platform":  # the real bring-up, whose platform step fails
        from boxmunge.userns import bringup
        monkeypatch.setattr(bringup, "_run", lambda *a, **kw: None)
        monkeypatch.setattr(bringup, "compose_up_platform", _bring_up_fails(error))
    else:
        monkeypatch.setattr(rb, where, _bring_up_fails(error))
    timers = FakeTimers()
    with pytest.raises(type(error), match=str(error)):
        rb.rollback(paths, daemon=_Daemon([]), timers=timers)
    j = load_journal(paths)
    assert j.phase == "quiesced" and j.failed == f"quiesced: {error}"
    assert timers.calls == [] and rb.migration_in_progress(paths) is not None
    (title, body, priority), = sent
    assert title == "userns rollback stopped" and priority == 1 and str(error) in body
    assert "marker is set" in body and "timers stay stopped" in body
    assert "re-run userns-rollback" in body


@pytest.mark.parametrize("journal, match", [
    (None, "no userns migration"),
    (Journal(FORWARD, "committed", S), "committed"),
    (Journal(FORWARD, "applied", S, items={"commit-before": "10"}), "finish it with userns-commit"),
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


def test_a_rollback_on_another_daemon_than_the_journalled_one_is_refused(paths, remapped,
                                                                       monkeypatch) -> None:
    events, _ = remapped
    monkeypatch.setattr(rb.uo, "remap_offset", lambda paths: 0)
    with pytest.raises(rb.MigrationError, match="not remapped at offset"):
        rb.rollback(paths, daemon=_Daemon(events), timers=FakeTimers())
    assert "quiesce" not in events


def test_the_rollback_scans_the_forward_binds_too(paths, remapped, monkeypatch) -> None:
    seen = {}
    monkeypatch.setattr(rb, "preflight", lambda *a, **kw: seen.update(kw) or Report())
    rb.rollback(paths, daemon=_Daemon(remapped[0]), timers=FakeTimers())
    assert seen["extra_binds"] and seen["extra_binds"][0].endswith("uploads")


def test_a_daemon_json_changed_during_the_soak_stops_the_rollback(paths, remapped,
                                                                monkeypatch) -> None:
    from boxmunge.userns.daemon_config import merged_daemon_json
    j = load_journal(paths)
    (rb.uo.ETC / "docker").mkdir(exist_ok=True)
    (rb.uo.ETC / "docker" / "daemon.json").write_bytes(merged_daemon_json(j.daemon_json.encode()))
    _REFUSE_SOAK_EDIT(j)  # the migration's own file: fine
    (rb.uo.ETC / "docker" / "daemon.json").write_text('{"debug": true}')
    with pytest.raises(rb.MigrationError, match="would drop that change"):
        _REFUSE_SOAK_EDIT(j)


def test_the_original_daemon_json_comes_back_with_its_mode(monkeypatch) -> None:
    from boxmunge.userns import switch as sw
    written = []
    monkeypatch.setattr(sw, "atomic_write_bytes", lambda path, data, mode, owner:
                        written.append((mode, owner)))
    (sw.uo.ETC / "docker").mkdir(exist_ok=True)
    sw.write_daemon_json("{}", [0o600, 0, 0])
    sw.write_daemon_json("{}")
    assert written[0] == (0o600, (0, 0)) and written[1][0] == 0o644


def test_the_box_running_again_is_reported(paths, monkeypatch) -> None:
    from boxmunge.userns import steps
    sent = []
    monkeypatch.setattr(steps, "notify", lambda p, title, body, **kw: sent.append((title, body)))
    monkeypatch.setattr(steps, "crowdsec_tails_caddy", lambda: None)
    j = Journal(ROLLBACK, "rolled-back", S, items={"rb-project:a": "up",
                                                  "rb-project:b": "failed: smoke"})
    steps.report_back(paths, j, "rb-project", "userns migration rolled back", "userns-rollback")
    assert sent == [("userns migration rolled back; 1 project(s) did not come back",
                     "a: up\nb: failed: smoke")]
