# SPDX-License-Identifier: Apache-2.0
"""The job runner: queue-scan recovery, lanes, the cap, worker_lost, tempfail."""
from __future__ import annotations

import itertools
import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.api import job_runner, job_writer
from boxmunge.api.job_runner import MAX_CONCURRENT_JOBS, run_runner
from boxmunge.api.job_worker import EX_TEMPFAIL
from boxmunge.api.worker_identity import WorkerIdentity
from boxmunge.release_txn import load_txn, options_text
from tests.api.fakes import read_audit
from tests.readiness_helpers import add_project, make_box, open_install

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
_ULID = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _id(n: int) -> str:
    return "01J" + "A" * 21 + _ULID[n // 32] + _ULID[n % 32]


class Box:
    """A box with a fake liveness table, collected alerts and errors, and a
    fake spawn whose children run scripted workers in threads."""

    def __init__(self, paths) -> None:
        self.paths = paths
        self.live: set[WorkerIdentity] = set()
        self.alerts: list[dict] = []
        self.errors: list[str] = []
        self.spawned: list[str] = []
        self.scripts: dict[str, object] = {}
        self.active: list[tuple[str, str | None]] = []
        self.peak: dict[str | None, int] = {}
        self.peak_total = 0
        self._lock = threading.Lock()
        self._pids = itertools.count(1000)

    def alive(self, identity: WorkerIdentity) -> bool:
        return identity in self.live

    def identity(self, boot: str = "boot-1") -> WorkerIdentity:
        return WorkerIdentity(boot, next(self._pids), 1)

    def publish(self, n: int, project: str | None = "myapp", action="project.backup") -> str:
        job_id = _id(n)
        record = job_writer.new_record(job_id, action, {"project": project} if project else {},
                                       "operator:ssh", project, NOW + timedelta(seconds=n))
        assert job_writer.publish(self.paths, record)
        return job_id

    def spawn(self, job_id: str) -> "FakeChild":
        self.spawned.append(job_id)
        script = self.scripts.get(job_id, work())
        return FakeChild(lambda: script(self, job_id))

    def record(self, job_id: str) -> dict:
        done = self.paths.jobs_dir / f"{job_id}.json"
        path = done if done.exists() else self.paths.jobs_queue / f"{job_id}.json"
        return json.loads(path.read_text())

    def run(self) -> int:
        return run_runner(self.paths, spawn=self.spawn, alive=self.alive)


class FakeChild:
    def __init__(self, target) -> None:
        self._code: int | None = None
        self._thread = threading.Thread(target=self._run, args=(target,))
        self._thread.start()

    def _run(self, target) -> None:
        self._code = target()

    def wait(self) -> int:
        self._thread.join()
        return self._code


def work(hold: float = 0.05, *, die: bool = False):
    """A worker that claims, works for *hold* seconds, and finishes the job
    succeeded (or, if *die*, is killed by SIGKILL mid-job)."""
    def script(box: Box, job_id: str) -> int:
        identity = box.identity()
        box.live.add(identity)
        record = job_writer.claim(box.paths, job_id, identity, NOW)
        assert record is not None
        with box._lock:
            lane = record["project"]
            box.active.append((job_id, lane))
            box.peak[lane] = max(box.peak.get(lane, 0),
                                 sum(1 for _j, p in box.active if p == lane))
            box.peak_total = max(box.peak_total, len(box.active))
        time.sleep(hold)
        with box._lock:
            box.active.remove((job_id, lane))
        if die:
            box.live.discard(identity)
            return -9
        job_writer.finish(box.paths, job_id, state="succeeded", error=None, result=None, now=NOW)
        box.live.discard(identity)
        return 0
    return script


def exits(code: int):
    def script(_box: Box, _job_id: str) -> int:
        return code
    return script


@pytest.fixture
def box(tmp_path, monkeypatch) -> Box:
    paths = make_box(tmp_path)
    add_project(paths, "myapp")
    add_project(paths, "blog")
    paths.audit_log.touch()
    b = Box(paths)
    monkeypatch.setattr(job_runner, "RUNNER_POLL_SECONDS", 0.01)
    monkeypatch.setattr(job_runner, "notify", lambda _p, title, body, **kw: b.alerts.append(
        {"title": title, "body": body, **kw}) or True)
    monkeypatch.setattr(job_runner, "log_error",
                        lambda _c, message, *_a, **_kw: b.errors.append(message))
    return b


def _lost_running(box: Box, n: int, action: str = "project.promote") -> str:
    """A job claimed by a worker of another boot: the box rebooted under it."""
    job_id = box.publish(n, action=action)
    assert job_writer.claim(box.paths, job_id, box.identity(boot="boot-0"), NOW)
    return job_id


def test_runs_every_queued_job_then_exits_when_queue_is_empty(box):
    ids = [box.publish(n) for n in range(3)]
    assert box.run() == 0
    assert box.spawned == ids
    assert [box.record(j)["state"] for j in ids] == ["succeeded"] * 3
    assert list(box.paths.jobs_queue.iterdir()) == []


def test_two_jobs_for_one_project_run_one_after_the_other(box):
    first, second = box.publish(0), box.publish(1)
    assert box.run() == 0
    assert box.spawned == [first, second]
    assert box.peak == {"myapp": 1}


def test_jobs_for_different_projects_run_concurrently_up_to_the_cap(box):
    projects = [f"p{n}" for n in range(MAX_CONCURRENT_JOBS + 2)]
    for p in projects:
        add_project(box.paths, p)
    ids = [box.publish(n, project=p) for n, p in enumerate(projects)]
    for job_id in ids:
        box.scripts[job_id] = work(0.3)
    assert box.run() == 0
    assert box.spawned == ids
    assert box.peak_total == MAX_CONCURRENT_JOBS


def test_jobs_without_a_project_share_one_lane(box):
    ids = [box.publish(n, project=None, action="host.thing") for n in range(2)]
    assert box.run() == 0
    assert box.spawned == ids
    assert box.peak == {None: 1}


def test_reboot_mid_promote_marks_lost_and_names_the_install_way_out(box):
    open_install(box.paths, "myapp")
    job_id = _lost_running(box, 0)
    assert box.run() == 0
    assert box.spawned == []
    record = box.record(job_id)
    assert not (box.paths.jobs_queue / f"{job_id}.json").exists()
    assert record["state"] == "failed" and record["error"]["code"] == "worker_lost"
    assert "was not run again" in record["error"]["message"]
    [alert] = box.alerts
    assert alert["title"] == f"boxmunge: job {job_id} (project.promote myapp) was cut off"
    assert alert["priority"] == 1
    assert record["error"]["message"] in alert["body"]
    assert options_text("myapp", load_txn(box.paths, "myapp")) in alert["body"]
    [audit] = [r for r in read_audit(box.paths) if r.get("job") == job_id]
    assert (audit["outcome"], audit["code"], audit["action"]) == \
        ("failed", "worker_lost", "project.promote")
    events = (box.paths.jobs_dir / f"{job_id}.events.jsonl").read_text().splitlines()
    assert json.loads(events[-1])["state"] == "failed"


def test_lost_job_without_an_install_names_the_actions_own_way_out(box):
    job_id = _lost_running(box, 0, action="project.backup")
    assert box.run() == 0
    [alert] = box.alerts
    assert "boxmunge backup myapp" in alert["body"]
    assert box.record(job_id)["state"] == "failed"


def test_lost_job_with_a_torn_events_file_is_still_failed_and_moved(box):
    job_id = _lost_running(box, 0)
    events = box.paths.jobs_dir / f"{job_id}.events.jsonl"
    events.write_text('{"seq": 1, "ts": "2026-11-15T12:00:00Z", "type": "state", '
                      '"state": "running"}\n{"seq": 2, "ty')
    assert box.run() == 0
    assert box.record(job_id)["error"]["code"] == "worker_lost"
    assert not (box.paths.jobs_queue / f"{job_id}.json").exists()
    assert any(str(events) in e for e in box.errors)
    assert len(box.alerts) == 1


def test_child_killed_by_signal_is_lost_immediately(box):
    job_id = box.publish(0)
    box.scripts[job_id] = work(die=True)
    assert box.run() == 0
    assert box.spawned == [job_id]
    assert box.record(job_id)["error"]["code"] == "worker_lost"
    [alert] = box.alerts
    assert "was cut off" in alert["title"]


def test_terminal_record_in_queue_is_moved_not_rerun(box, monkeypatch):
    job_id = box.publish(0)
    assert job_writer.claim(box.paths, job_id, box.identity(), NOW)
    with monkeypatch.context() as m:
        m.setattr(job_writer, "_move_to_done", lambda *_a: (_ for _ in ()).throw(OSError("x")))
        with pytest.raises(OSError):
            job_writer.finish(box.paths, job_id, state="succeeded", error=None, result=None,
                              now=NOW)
    assert box.run() == 0
    assert box.spawned == [] and box.alerts == []
    assert not (box.paths.jobs_queue / f"{job_id}.json").exists()
    assert box.record(job_id)["state"] == "succeeded"


def test_running_job_of_a_live_foreign_worker_is_left_and_waited_for(box):
    foreign_job, queued = box.publish(0), box.publish(1)
    foreign = box.identity()
    box.live.add(foreign)
    assert job_writer.claim(box.paths, foreign_job, foreign, NOW)
    finished_at: list[float] = []

    def foreign_worker() -> None:
        time.sleep(0.2)
        job_writer.finish(box.paths, foreign_job, state="succeeded", error=None, result=None,
                          now=NOW)
        finished_at.append(time.monotonic())
        box.live.discard(foreign)

    started_at: list[float] = []

    def script(b: Box, job_id: str) -> int:
        started_at.append(time.monotonic())
        return work()(b, job_id)

    box.scripts[queued] = script
    thread = threading.Thread(target=foreign_worker)
    thread.start()
    assert box.run() == 0
    thread.join()
    assert box.spawned == [queued]  # never the foreign worker's job
    assert started_at[0] >= finished_at[0]  # its project's lane was busy until then
    assert box.record(foreign_job)["state"] == "succeeded" and box.alerts == []


def test_unexpected_queue_entry_is_set_aside_and_alerted(box, tmp_path):
    queue = box.paths.jobs_queue
    queue.mkdir(parents=True)
    (queue / "notes.txt").write_text("hi")
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    os.symlink(target, queue / f"{_id(7)}.json")
    (queue / "subdir").mkdir()
    assert box.run() == 0
    assert box.spawned == []
    assert list(queue.iterdir()) == []
    rejected = sorted(p.name.rsplit(".", 1)[0] for p in box.paths.jobs_rejected.iterdir())
    assert rejected == sorted(["notes.txt", f"{_id(7)}.json", "subdir"])
    assert target.read_text() == "{}"
    assert [p for p in box.paths.jobs_rejected.iterdir() if p.is_symlink()]
    assert len(box.alerts) == 3 and len(box.errors) == 3
    for name in ("notes.txt", "subdir"):
        [alert] = [a for a in box.alerts if name in a["body"]]
        assert "set aside" in alert["body"]


def test_unreadable_queue_record_is_set_aside_and_alerted(box):
    job_id = box.publish(0)
    queued = box.paths.jobs_queue / f"{job_id}.json"
    queued.write_text("not json")
    assert box.run() == 0
    assert box.spawned == []
    assert not queued.exists()
    [aside] = list(box.paths.jobs_rejected.iterdir())
    assert aside.read_text() == "not json"
    [alert] = box.alerts
    assert job_id in alert["body"] and "set aside" in alert["body"]


def test_job_still_queued_after_its_worker_exited_is_not_respawned(box):
    stuck, other = box.publish(0), box.publish(1, project="blog")
    box.scripts[stuck] = exits(1)
    assert box.run() == 1
    assert box.spawned == [stuck, other]
    assert box.record(stuck)["state"] == "queued"
    assert box.record(other)["state"] == "succeeded"
    [alert] = box.alerts
    assert stuck in alert["body"] and "exited 1" in alert["body"]


def test_runner_exits_after_a_tempfail_so_systemd_restarts_it_on_new_code(box):
    held, running, later = box.publish(0), box.publish(1, project="blog"), box.publish(2)
    box.scripts[held] = exits(EX_TEMPFAIL)
    box.scripts[running] = work(0.3)
    assert box.run() == 0
    assert box.spawned == [held, running]  # nothing started after the tempfail
    assert box.record(running)["state"] == "succeeded"  # the running one was waited for
    assert box.record(held)["state"] == "queued" and box.record(later)["state"] == "queued"
    assert box.alerts == []


def test_spawn_runs_the_worker_command_with_inherited_output(monkeypatch):
    seen: list = []
    monkeypatch.setattr(job_runner.subprocess, "Popen", lambda argv, **kw: seen.append(
        (argv, kw)) or "child")
    assert job_runner._spawn_worker(_id(0)) == "child"
    [(argv, kw)] = seen
    assert argv == [sys.executable, "-m", "boxmunge", "_run-job", _id(0)]
    assert kw == {}


def _main(argv: list[str], monkeypatch) -> int:
    from boxmunge import cli
    monkeypatch.setattr(sys, "argv", ["boxmunge", "_job-runner", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_job_runner_command_exits_with_the_runners_code(paths, monkeypatch):
    from boxmunge.paths import BoxPaths
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    seen: list = []
    monkeypatch.setattr(job_runner, "run_runner", lambda p: seen.append(p.root) or 1)
    assert _main([], monkeypatch) == 1
    assert seen == [paths.root]


def test_job_runner_command_takes_no_arguments(monkeypatch, capsys):
    monkeypatch.setattr(job_runner, "run_runner", lambda *a, **kw: pytest.fail("ran"))
    assert _main(["extra"], monkeypatch) == 2
    assert "ERROR:" in capsys.readouterr().err
