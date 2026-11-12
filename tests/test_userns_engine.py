"""The forward engine: phase order, resume after a crash at each step, refusals."""
from __future__ import annotations

import json
import os

import pytest

from boxmunge.fileutil import project_lock
from boxmunge.userns import engine as en
from boxmunge.userns import switch as sw
from boxmunge.userns.inventory import ImageEntry, Inventory, VolumeEntry
from boxmunge.userns.journal import FORWARD, ROLLBACK, Journal, load_journal, save_journal
from boxmunge.userns.preflight import Report
from boxmunge.userns.shift import Scan, ShiftReport
from tests.integration.userns.dockerd import FakeTimers

S = 1048576
_REAL_SWITCH = en._switch  # the box fixture stubs it
STEPS = ["save_all", "_prepare", "quiesce", "_switch", "_rebuild", "bring_up"]


class _Daemon:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def stop(self) -> None:
        self.calls.append("stop")

    def start(self) -> None:
        self.calls.append("start")


@pytest.fixture(autouse=True)
def flushes(monkeypatch):
    """The durability barrier, recorded (it flushes real filesystems)."""
    seen: list[str] = []
    monkeypatch.setattr(en, "barrier", lambda paths, j, images_dir: seen.append(j.phase))
    return seen


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
    monkeypatch.setattr(en, "disk_before_downtime", lambda inv, d: None)

    def step(name, phase):
        def run(*args, **kwargs):
            calls.append(name)
            if crash.pop(name, False):
                raise RuntimeError(f"power cut in {name}")
            j = next((a for a in args if isinstance(a, Journal)), None)
            save = next((a for a in args if getattr(a, "__name__", "") == "save"), None)
            if j is not None and phase:
                j.phase = phase
                save() if save else save_journal(paths, j)
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
    assert calls.index("_prepare") < calls.index("quiesce")


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


def test_each_phase_is_flushed_before_the_journal_records_it(paths, box, monkeypatch,
                                                             flushes) -> None:
    events: list[tuple[str, str]] = []
    monkeypatch.setattr(en, "barrier", lambda p, j, d: events.append(("flush", j.phase)))
    real = en.save_journal
    monkeypatch.setattr(en, "save_journal", lambda p, j: (events.append(("save", j.phase)),
                                                          real(p, j)))
    _migrate(paths)
    for phase in ("quiesced", "switched", "rebuilt", "applied"):
        at = events.index(("save", phase))
        assert events[at - 1] == ("flush", phase), (phase, events)


def test_a_flush_that_fails_leaves_the_journal_where_the_disk_is(paths, box,
                                                                 monkeypatch) -> None:
    def barrier(p, j, d):
        if j.phase == "switched":
            raise en.NotDurable("cannot flush the filesystem holding /var/lib/docker: EIO")
    monkeypatch.setattr(en, "barrier", barrier)
    with pytest.raises(en.NotDurable, match="EIO"):
        _migrate(paths)
    j = load_journal(paths)
    assert j.phase == "quiesced" and j.failed is None


def test_rerun_after_applied_refuses(paths, box) -> None:
    """Review Focus 4."""
    _migrate(paths)
    with pytest.raises(en.MigrationError, match="already applied"):
        _migrate(paths)


def test_a_rollback_in_progress_blocks_the_migration(paths, box) -> None:
    save_journal(paths, Journal(ROLLBACK, "rb-saved", S))
    with pytest.raises(en.MigrationError, match="finish it: userns-rollback"):
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
    timers = FakeTimers()
    with pytest.raises(en.MigrationError, match="restarted on its old root"):
        en._switch(paths, j, inv, daemon, timers, lambda: save_journal(paths, j))
    assert (etc / "docker" / "daemon.json").read_text() == original
    assert sw.uo.recorded_offset(paths) is None
    assert daemon.calls == ["stop", "start", "stop", "start"] and brought == ["restart"]
    assert timers.calls[-1][0] == "restore"  # the box runs again, so do its timers
    assert load_journal(paths).phase == "started"  # not "prepared": see the next test


def test_the_switch_writes_the_merged_config_and_the_record(paths, monkeypatch,
                                                           tmp_path) -> None:
    etc, _original, j = _real_switch_box(paths, monkeypatch, tmp_path)
    monkeypatch.setattr(en.uo, "remap_offset", lambda paths: S)
    daemon = _Daemon()
    en._switch(paths, j, Inventory("overlay2", "", str(tmp_path), "29.9.0"), daemon,
               FakeTimers(), lambda: save_journal(paths, j))
    doc = json.loads((etc / "docker" / "daemon.json").read_text())
    assert doc["userns-remap"] == "boxmunge-remap:boxmunge-remap" and doc["log-driver"]
    assert sw.uo.recorded_offset(paths) == S and load_journal(paths).phase == "switched"
    assert daemon.calls == ["stop", "start"]


@pytest.mark.parametrize("left", ["both", "merged daemon.json only", "record only"])
def test_a_crash_inside_the_switch_is_undone_before_phase_0_runs_again(paths, monkeypatch,
                                                                      tmp_path, left) -> None:
    """The switch writes the merged daemon.json, then the record (undoing it,
    the original, then drops the record): a kill can leave either alone."""
    etc, original, j = _real_switch_box(paths, monkeypatch, tmp_path)
    from boxmunge.userns.daemon_config import merged_daemon_json
    if left != "record only":
        (etc / "docker" / "daemon.json").write_bytes(merged_daemon_json(original.encode()))
    if left != "merged daemon.json only":
        sw.uo.write_offset_record(paths, S)
    assert sw.switch_interrupted(paths, original)
    daemon = _Daemon()
    assert sw.ensure_prior(paths, original, S, daemon) == original
    assert (etc / "docker" / "daemon.json").read_text() == original
    assert sw.uo.recorded_offset(paths) is None and daemon.calls == ["stop", "start"]
    monkeypatch.setattr(sw, "daemon_answers", lambda: True)
    assert not sw.switch_interrupted(paths, original)
    assert sw.ensure_prior(paths, original, S, daemon) == original
    assert daemon.calls == ["stop", "start"]  # nothing left to undo


def test_the_operators_fix_to_daemon_json_becomes_the_prior_config(paths, monkeypatch,
                                                                   tmp_path) -> None:
    """After a remapped daemon would not start, the operator edits daemon.json
    and runs the migration again: their edit is kept, not undone."""
    etc, original, _j = _real_switch_box(paths, monkeypatch, tmp_path)
    fixed = '{"log-driver": "json-file", "iptables": true}'
    (etc / "docker" / "daemon.json").write_text(fixed)
    monkeypatch.setattr(sw, "daemon_answers", lambda: True)
    daemon = _Daemon()
    assert sw.ensure_prior(paths, original, S, daemon) == fixed
    assert (etc / "docker" / "daemon.json").read_text() == fixed and daemon.calls == []
    (etc / "docker" / "daemon.json").write_text('{"userns-remap": "default"}')
    with pytest.raises(en.MigrationError, match="names a userns-remap"):
        sw.ensure_prior(paths, original, S, daemon)


def test_writing_daemon_json_makes_its_directory_roots(paths, monkeypatch) -> None:
    made = []
    monkeypatch.setattr(sw, "atomic_write_bytes", lambda path, data, **kw: made.append(path))
    assert not (sw.uo.ETC / "docker").exists()
    sw.write_daemon_json("{}")
    assert oct((sw.uo.ETC / "docker").stat().st_mode & 0o777) == "0o755"
    assert made == [sw.uo.ETC / "docker" / "daemon.json"]


def test_a_failed_backup_stops_before_any_downtime(paths, monkeypatch, tmp_path) -> None:
    paths.project_dir("shop").mkdir(parents=True)
    paths.project_manifest("shop").write_text("project: shop\n")
    monkeypatch.setattr("boxmunge.commands.backup_cmd.backup_locked", lambda p, paths, kind: 1)
    inv = Inventory("overlay2", "", str(tmp_path), "29.9.0", projects=["shop"])
    with pytest.raises(en.MigrationError, match="pre-migration backup of shop failed"):
        en._backups(paths, inv)


def test_a_pause_record_that_cannot_be_read_stops_before_any_downtime(
        paths, monkeypatch, tmp_path) -> None:
    """Not taken for "paused" (which skips the project's backup): read, and
    refused when it cannot be."""
    paths.project_dir("shop").mkdir(parents=True)
    paths.project_manifest("shop").write_text("project: shop\n")
    paths.project_paused_state("shop").symlink_to(tmp_path / "gone.json")
    monkeypatch.setattr("boxmunge.commands.backup_cmd.backup_locked",
                        lambda p, paths, kind: pytest.fail("backed up past the record"))
    inv = Inventory("overlay2", "", str(tmp_path), "29.9.0", projects=["shop"])
    with pytest.raises(en.MigrationError, match="symlink.*nothing was stopped"):
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
    monkeypatch.setattr(en, "scan_tree", lambda *a, **kw: Scan([], 1, {"x": 0o4755}))
    shifted = []
    monkeypatch.setattr(en, "shift_tree", lambda tree, s, d, setid, resumed, scan: shifted.append(
        (tree, setid)) or ShiftReport())
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


def test_a_second_failed_switch_restarts_every_project_again(paths, monkeypatch, tmp_path) -> None:
    _etc, _original, j = _real_switch_box(paths, monkeypatch, tmp_path)
    j.items["restart:shop"] = "up"  # from an earlier failed switch
    monkeypatch.setattr(en.uo, "remap_offset", lambda paths: 0)
    seen = []
    monkeypatch.setattr(en, "bring_up", lambda paths, inv, j, save, **kw: seen.append(dict(j.items)))
    with pytest.raises(en.MigrationError):
        en._switch(paths, j, Inventory("overlay2", "", str(tmp_path), "29.9.0"), _Daemon(),
                   FakeTimers(), lambda: save_journal(paths, j))
    assert seen == [{}]


def test_a_failure_before_the_downtime_leaves_the_timers_running(paths, box) -> None:
    calls, crash = box
    crash["_prepare"] = True
    timers = FakeTimers()
    with pytest.raises(RuntimeError, match="power cut"):
        _migrate(paths, timers)
    assert timers.calls == []


def test_a_stopped_daemons_bridges_are_deleted_as_a_reboot_would(monkeypatch, tmp_path) -> None:
    sysnet = tmp_path / "net"
    (sysnet / "br-0123456789ab").mkdir(parents=True)
    monkeypatch.setattr(sw, "_SYS_NET", sysnet)
    ran = []
    monkeypatch.setattr(sw.subprocess, "run", lambda cmd, **kw: ran.append(cmd) or
                        type("R", (), {"returncode": 0, "stderr": ""})())
    sw.drop_bridges(["br-0123456789ab", "br-gone"])
    assert ran == [["ip", "link", "delete", "br-0123456789ab"]]


def test_the_marker_holds_from_the_quiesce_until_the_box_runs_again(paths, box, monkeypatch) -> None:
    calls, crash = box
    from boxmunge.userns.marker import migration_in_progress
    seen = {}
    real_prepare, real_quiesce = en._prepare, en.quiesce
    monkeypatch.setattr(en, "_prepare", lambda *a: (seen.update(prepare=migration_in_progress(
        paths)), real_prepare(*a)))
    monkeypatch.setattr(en, "quiesce", lambda inv: (seen.update(quiesce=migration_in_progress(
        paths)), real_quiesce(inv)))
    crash["_rebuild"] = True
    with pytest.raises(RuntimeError):
        _migrate(paths)
    assert seen == {"prepare": None, "quiesce": en.FINISH}  # backups run before it
    assert migration_in_progress(paths) == en.FINISH  # stopped part-way: it stays
    _migrate(paths)
    assert migration_in_progress(paths) is None


def test_a_quiesce_failure_says_the_timers_are_stopped(paths, box, monkeypatch) -> None:
    calls, crash = box
    sent = []
    monkeypatch.setattr(en, "notify", lambda p, t, body, **kw: sent.append(body) or True)
    crash["quiesce"] = True
    with pytest.raises(RuntimeError):
        _migrate(paths)
    assert "timers are stopped" in sent[0] and "every project command refuses" in sent[0]


def test_a_resume_after_an_undone_switch_backs_up_again(paths, box, monkeypatch) -> None:
    """The box runs on its old root after SwitchUndone, maybe for weeks: the
    backups taken before the failed switch are no protection for the next one."""
    calls, _ = box
    monkeypatch.setattr(en, "_switch", _REAL_SWITCH)
    monkeypatch.setattr(en.uo, "remap_offset", lambda paths: S)
    monkeypatch.setattr(en, "back_to_prior", lambda *a: None)
    attempts = []

    def to_remapped(*a):
        attempts.append(1)
        if len(attempts) == 1:
            raise en.MigrationError("dockerd exited")

    monkeypatch.setattr(en, "to_remapped", to_remapped)
    with pytest.raises(en.SwitchUndone):
        _migrate(paths)
    assert calls.count("_prepare") == 1
    assert _migrate(paths).phase == "applied"
    assert calls.count("_prepare") == 2


def test_a_switch_undone_clears_the_marker(paths, monkeypatch, tmp_path) -> None:
    from boxmunge.userns.marker import migration_in_progress, set_marker
    _etc, _original, j = _real_switch_box(paths, monkeypatch, tmp_path)
    set_marker(paths, en.FINISH)
    monkeypatch.setattr(en.uo, "remap_offset", lambda paths: 0)
    monkeypatch.setattr(en, "bring_up", lambda *a, **kw: None)
    with pytest.raises(en.SwitchUndone):
        en._switch(paths, j, Inventory("overlay2", "", str(tmp_path), "29.9.0"), _Daemon(),
                   FakeTimers(), lambda: save_journal(paths, j))
    assert migration_in_progress(paths) is None


def test_too_little_space_after_the_backups_stops_before_the_downtime(paths, box,
                                                                      monkeypatch) -> None:
    calls, _ = box
    from boxmunge.userns import steps
    monkeypatch.setattr(en, "disk_before_downtime", steps.disk_before_downtime)
    monkeypatch.setattr(steps, "disk", lambda inv, r, d: r.refusals.append("10 bytes free"))
    with pytest.raises(en.MigrationError, match="nothing was stopped"):
        _migrate(paths)
    assert "quiesce" not in calls and "_prepare" in calls


def test_crowdsec_must_tail_the_recreated_caddy(monkeypatch, tmp_path) -> None:
    from boxmunge.userns import steps
    log = tmp_path / "crowdsec.log"
    log.write_text("old line\n")
    monkeypatch.setattr(steps, "CROWDSEC_LOG", log)
    monkeypatch.setattr(steps, "_CROWDSEC_WAIT", 0.2)
    monkeypatch.setattr(steps.shutil, "which", lambda name: "/usr/bin/cscli")
    ran = []
    monkeypatch.setattr(steps.subprocess, "run", lambda cmd, **kw: ran.append(cmd) or
                        type("R", (), {"returncode": 0, "stderr": ""})())
    assert "is not reading boxmunge-caddy" in steps.crowdsec_tails_caddy()
    assert ran == [["systemctl", "restart", "crowdsec"]]
    def restarted(cmd, **kw):
        log.write_text('old line\nlevel=info msg="start tail for container boxmunge-caddy"\n')
        return type("R", (), {"returncode": 0, "stderr": ""})()
    monkeypatch.setattr(steps.subprocess, "run", restarted)
    assert steps.crowdsec_tails_caddy() is None
    monkeypatch.setattr(steps.shutil, "which", lambda name: None)
    assert steps.crowdsec_tails_caddy() is None  # not installed: nothing to check


def test_an_inverse_shift_journals_what_it_left_alone(monkeypatch, tmp_path) -> None:
    """Entries whose ids are in neither range keep their owners (there is no
    inverse to give them): the rollback says so instead of dropping it."""
    from boxmunge.userns.shift import Direction, Scan
    left = [f"f{i} (300000:300000)" for i in range(7)]
    monkeypatch.setattr(en, "scan_tree", lambda tree, s, d, resumed: Scan([], 0))
    monkeypatch.setattr(en, "shift_tree", lambda *a, **kw: ShiftReport(7, 0, list(left)))
    j = Journal(ROLLBACK, "rb-quiesced", S)
    saved = []
    en.shift_journalled(j, tmp_path, Direction.INVERSE, lambda: saved.append(dict(j.items)),
                        f"rb:{tmp_path}")
    note = j.items[f"left:rb:{tmp_path}"]
    assert note.startswith("7 entries with ids outside both ranges keep their owners")
    assert "f0 (300000:300000)" in note and "f6" not in note and "and 2 more" in note
    assert saved[-1] == j.items


def test_a_shift_that_left_nothing_alone_journals_nothing(monkeypatch, tmp_path) -> None:
    from boxmunge.userns.shift import Direction, Scan
    monkeypatch.setattr(en, "scan_tree", lambda tree, s, d, resumed: Scan([], 0))
    monkeypatch.setattr(en, "shift_tree", lambda *a, **kw: ShiftReport(3, 3, []))
    j = Journal(ROLLBACK, "rb-quiesced", S, items={f"left:rb:{tmp_path}": "from a run before"})
    en.shift_journalled(j, tmp_path, Direction.INVERSE, lambda: None, f"rb:{tmp_path}")
    assert not any(k.startswith("left:") for k in j.items)


def test_a_journalled_shift_walks_the_tree_twice(monkeypatch, tmp_path) -> None:
    """One scan (the refusals and the setuid list) and one shift: the scan
    that fills the journal is the one the shift refuses on."""
    from boxmunge.userns import shift
    from boxmunge.userns.shift import Direction
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "f").write_text("x")
    walks = []
    real_walk = shift.walk
    monkeypatch.setattr(shift, "walk", lambda root, visit: (walks.append(root),
                                                           real_walk(root, visit))[1])
    # The scan's Linux-only probes; an inverse shift of the caller's own files chowns nothing.
    monkeypatch.setattr(shift, "mount_points_under", lambda root: [])
    monkeypatch.setattr(shift, "_xattrs", lambda fd: [])
    monkeypatch.setattr(shift, "_flags", lambda fd: 0)
    j = Journal(ROLLBACK, "rb-quiesced", S)
    saved = []
    en.shift_journalled(j, tmp_path, Direction.INVERSE, lambda: saved.append(dict(j.setid)),
                        f"rb:{tmp_path}")
    assert walks == [tmp_path, tmp_path]
    assert saved == [{f"rb:{tmp_path}": {}}]  # journalled once, before the shift


def test_a_refused_resumed_shift_journals_its_list_first_and_walks_no_further(monkeypatch,
                                                                              tmp_path) -> None:
    """The scan handed to the shift is the one it refuses on, before any
    change. Of a tree whose shift began, the list is in the journal by then,
    as it was when the shift scanned for itself."""
    from boxmunge.userns import shift
    from boxmunge.userns.shift import Direction, Scan, ShiftRefused
    monkeypatch.setattr(en, "scan_tree", lambda tree, s, d, resumed: Scan(
        ["dev: device node"], 2, {"suid": 0o4755}))
    monkeypatch.setattr(shift, "walk", lambda root, visit: pytest.fail("walked a refused tree"))
    j = Journal(FORWARD, "switched", S, setid={str(tmp_path): {}})
    saved = []
    with pytest.raises(ShiftRefused, match="dev: device node"):
        en.shift_journalled(j, tmp_path, Direction.FORWARD, lambda: saved.append(dict(j.setid)),
                            str(tmp_path))
    assert saved == [{str(tmp_path): {"suid": 0o4755}}]


def test_a_refused_first_scan_journals_no_setid_list(monkeypatch, tmp_path) -> None:
    """A tree's list in the journal marks its shift as begun, and a begun
    shift's scan accepts ids already in the remap range. A tree whose first
    scan refused was never shifted: the next run must scan it as strictly."""
    from boxmunge.userns import shift
    from boxmunge.userns.shift import Direction, ShiftRefused
    (tmp_path / "outside").write_text("x")
    tree = tmp_path / "tree"
    tree.mkdir()
    os.link(tmp_path / "outside", tree / "linked")
    monkeypatch.setattr(shift, "mount_points_under", lambda root: [])  # Linux-only probes
    monkeypatch.setattr(shift, "_xattrs", lambda fd: [])
    monkeypatch.setattr(shift, "_flags", lambda fd: 0)
    scans = []
    real_scan = en.scan_tree
    monkeypatch.setattr(en, "scan_tree", lambda tree, s, d, resumed: (
        scans.append(resumed), real_scan(tree, s, d, resumed=resumed))[1])
    j = Journal(FORWARD, "switched", S)
    for _ in range(2):
        with pytest.raises(ShiftRefused, match="hard link to a file outside the tree"):
            en.shift_journalled(j, tree, Direction.FORWARD, lambda: pytest.fail("journalled"),
                                str(tree))
    assert str(tree) not in j.setid and scans == [False, False]
