"""The forward engine: phase order, resume after a crash at each step, refusals."""
from __future__ import annotations

import json

import pytest

from boxmunge.fileutil import project_lock
from boxmunge.userns import engine as en
from boxmunge.userns import switch as sw
from boxmunge.userns.inventory import ImageEntry, Inventory, VolumeEntry
from boxmunge.userns.journal import FORWARD, ROLLBACK, Journal, load_journal, save_journal
from boxmunge.userns.preflight import Report
from tests.integration.userns.dockerd import FakeTimers

S = 1048576
STEPS = ["save_all", "_prepare", "quiesce", "_switch", "_rebuild", "bring_up"]


class _Daemon:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def stop(self) -> None:
        self.calls.append("stop")

    def start(self) -> None:
        self.calls.append("start")


@pytest.fixture
def box(paths, monkeypatch, tmp_path):
    calls: list[str] = []
    crash: dict[str, bool] = {}
    inv = Inventory("overlay2", "", str(tmp_path / "docker"), "29.9.0", projects=["shop"])
    monkeypatch.setattr(en, "load_registered_projects", lambda p: {"shop"})
    monkeypatch.setattr(en, "take_inventory", lambda p: inv)
    monkeypatch.setattr(en, "preflight", lambda *a, **kw: Report())
    monkeypatch.setattr(en.uo, "allocate_offset", lambda etc, ids: S)
    monkeypatch.setattr(en, "prior_store", lambda inv: {"driver": "overlay2", "driver_type": "",
                                                        "store_root": "/x", "size": 0})
    monkeypatch.setattr(en, "notify", lambda *a, **kw: True)
    monkeypatch.setattr(en, "_final", lambda paths, j, results: calls.append("final"))
    monkeypatch.setattr(en, "ensure_prior", lambda *a: calls.append("ensure_prior"))
    monkeypatch.setattr(en, "_ensure_remapped", lambda *a: calls.append("ensure_remapped"))

    def step(name, phase):
        def run(*args, **kwargs):
            calls.append(name)
            if crash.pop(name, False):
                raise RuntimeError(f"power cut in {name}")
            j = next((a for a in args if isinstance(a, Journal)), None)
            if j is not None and phase:
                j.phase = phase
                save_journal(paths, j)
            return {}
        return run
    for name, phase in [("_prepare", "prepared"), ("_switch", "switched"),
                        ("_rebuild", "rebuilt"), ("bring_up", None), ("save_all", None),
                        ("quiesce", None)]:
        monkeypatch.setattr(en, name, step(name, phase))
    return calls, crash


def _migrate(paths, timers=None):
    return en.migrate(paths, daemon=_Daemon(), timers=timers or FakeTimers())


def test_a_clean_run_goes_through_every_phase(paths, box) -> None:
    calls, _ = box
    timers = FakeTimers()
    j = _migrate(paths, timers)
    assert calls == [*STEPS, "final"] and j.phase == "applied" and j.applied_at
    assert load_journal(paths).timers == FakeTimers().state()
    assert [c[0] for c in timers.calls] == ["stop", "restore"]


@pytest.mark.parametrize("step", STEPS)
def test_resume_after_a_crash_in_each_step(paths, box, step) -> None:
    calls, crash = box
    crash[step] = True
    with pytest.raises(RuntimeError, match="power cut"):
        _migrate(paths)
    assert load_journal(paths).failed.endswith(f"power cut in {step}")
    calls.clear()
    assert _migrate(paths).phase == "applied"
    redone = [s for s in calls if s in STEPS[:STEPS.index(step)]]
    # Before the switch, the tars and the quiesce are checked again (idempotent).
    assert set(redone) <= {"save_all", "quiesce"}
    assert ("ensure_prior" in calls) == (STEPS.index(step) <= STEPS.index("_switch"))
    assert load_journal(paths).failed is None


def test_rerun_after_applied_refuses(paths, box) -> None:
    """Review Focus 4."""
    _migrate(paths)
    with pytest.raises(en.MigrationError, match="already applied"):
        _migrate(paths)


def test_a_rollback_in_progress_blocks_the_migration(paths, box) -> None:
    save_journal(paths, Journal(ROLLBACK, "rb-saved", S))
    with pytest.raises(en.MigrationError, match="finish it with userns-rollback"):
        _migrate(paths)


def test_a_rolled_back_box_starts_over(paths, box) -> None:
    save_journal(paths, Journal(ROLLBACK, "rolled-back", S, items={"rb-volume:x": "restored"}))
    j = _migrate(paths)
    assert j.direction == FORWARD and "rb-volume:x" not in j.items


def test_a_held_project_lock_stops_it_before_anything(paths, box) -> None:
    calls, _ = box
    with project_lock("shop", paths):
        with pytest.raises(Exception, match="in progress"):
            _migrate(paths)
    assert calls == [] and load_journal(paths) is None


def _real_switch_box(paths, monkeypatch, tmp_path):
    etc = sw.uo.ETC
    (etc / "docker").mkdir(exist_ok=True)
    original = '{"log-driver": "json-file"}'
    (etc / "docker" / "daemon.json").write_text(original)
    paths.config_file.write_text("hostname: h\nadmin_email: a@b.c\n")
    j = Journal(FORWARD, "quiesced", S, daemon_json=original)
    save_journal(paths, j)
    return etc, original, j


def test_a_remapped_daemon_that_will_not_start_puts_everything_back(paths, monkeypatch,
                                                                    tmp_path) -> None:
    etc, original, j = _real_switch_box(paths, monkeypatch, tmp_path)
    daemon = _Daemon()
    starts = {"n": 0}

    def start():
        starts["n"] += 1
        daemon.calls.append("start")
        if starts["n"] == 1:
            raise en.MigrationError("dockerd exited: userns remapping needs subuid")
    daemon.start = start
    brought = []
    monkeypatch.setattr(en, "bring_up", lambda *a, **kw: brought.append(kw["prefix"]))
    inv = Inventory("overlay2", "", str(tmp_path), "29.9.0")
    with pytest.raises(en.MigrationError, match="restarted on its old root"):
        en._switch(paths, j, inv, daemon, lambda: save_journal(paths, j))
    assert (etc / "docker" / "daemon.json").read_text() == original
    assert sw.uo.recorded_offset(paths) is None
    assert daemon.calls == ["stop", "start", "stop", "start"] and brought == ["restart"]
    assert load_journal(paths).phase == "prepared"


def test_the_switch_writes_the_merged_config_and_the_record(paths, monkeypatch,
                                                           tmp_path) -> None:
    etc, _original, j = _real_switch_box(paths, monkeypatch, tmp_path)
    monkeypatch.setattr(en.uo, "remap_offset", lambda paths: S)
    daemon = _Daemon()
    en._switch(paths, j, Inventory("overlay2", "", str(tmp_path), "29.9.0"), daemon,
               lambda: save_journal(paths, j))
    doc = json.loads((etc / "docker" / "daemon.json").read_text())
    assert doc["userns-remap"] == "boxmunge-remap:boxmunge-remap" and doc["log-driver"]
    assert sw.uo.recorded_offset(paths) == S and load_journal(paths).phase == "switched"
    assert daemon.calls == ["stop", "start"]


def test_a_crash_inside_the_switch_is_undone_before_phase_0_runs_again(paths, monkeypatch,
                                                                      tmp_path) -> None:
    etc, original, j = _real_switch_box(paths, monkeypatch, tmp_path)
    (etc / "docker" / "daemon.json").write_text('{"userns-remap": "boxmunge-remap:boxmunge-remap"}')
    sw.uo.write_offset_record(paths, S)
    daemon = _Daemon()
    assert sw.ensure_prior(paths, original, S, daemon)
    assert (etc / "docker" / "daemon.json").read_text() == original
    assert sw.uo.recorded_offset(paths) is None and daemon.calls == ["stop", "start"]
    monkeypatch.setattr(sw, "daemon_answers", lambda: True)
    assert not sw.ensure_prior(paths, original, S, daemon)  # nothing left to undo


def test_a_failed_backup_stops_before_any_downtime(paths, monkeypatch, tmp_path) -> None:
    paths.project_dir("shop").mkdir(parents=True)
    paths.project_manifest("shop").write_text("project: shop\n")
    monkeypatch.setattr("boxmunge.commands.backup_cmd.backup_locked", lambda p, paths, kind: 1)
    inv = Inventory("overlay2", "", str(tmp_path), "29.9.0", projects=["shop"])
    with pytest.raises(en.MigrationError, match="pre-migration backup of shop failed"):
        en._backups(paths, inv)


def test_rebuild_resumes_a_volume_part_way(paths, monkeypatch, tmp_path) -> None:
    root = tmp_path / "docker"
    (root / "volumes" / "v" / "_data").mkdir(parents=True)
    (root / "volumes" / "v" / "_data" / "row").write_text("42")
    new = root / f"{S}.{S}" / "volumes" / "v" / "_data"
    events = []
    monkeypatch.setattr(en, "_network", lambda inv: events.append("network"))
    monkeypatch.setattr(en, "load_all", lambda *a: events.append("load"))
    monkeypatch.setattr(en, "recreate", lambda v: (events.append("create"),
                                                   new.mkdir(parents=True, exist_ok=True)))
    monkeypatch.setattr(en, "scan_tree", lambda *a: type("S", (), {"setid": {"x": 0o4755}})())
    shifted = []
    monkeypatch.setattr(en, "shift_tree", lambda tree, s, d, setid: shifted.append((tree, setid)))
    monkeypatch.setattr(en, "set_caddyfile_mode", lambda paths, mode: events.append(oct(mode)))
    inv = Inventory("overlay2", "", str(root), "29.9.0", images=[ImageEntry("sha256:a", ["a:1"], 1, True)],
                    volumes=[VolumeEntry("v", "local", {}, {}, "", True, False, True),
                             VolumeEntry("e" * 64, "local", {}, {}, "", True, True, False)],
                    record_data=[str(tmp_path / "uploads")])
    (tmp_path / "uploads").mkdir()
    j = Journal(FORWARD, "switched", S, caddyfile_mode=0o640, items={"volume:v": "created"})
    save_journal(paths, j)
    # The crash came after the rename, before the journal said "moved".
    new.parent.mkdir(parents=True)
    (root / "volumes" / "v" / "_data").rename(new)
    en._rebuild(paths, j, inv, tmp_path / "img", lambda: save_journal(paths, j))
    assert (new / "row").read_text() == "42"
    assert events == ["network", "load", "0o644", "create"]
    assert [t for t, _ in shifted] == [new, tmp_path / "uploads"]
    assert load_journal(paths).setid[str(new)] == {"x": 0o4755}
    assert j.items == {"volume:v": "shifted", "network": "created", "caddyfile": "0644",
                       f"bind:{tmp_path / 'uploads'}": "shifted"}
    assert j.phase == "rebuilt"
