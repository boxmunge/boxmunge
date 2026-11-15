# SPDX-License-Identifier: Apache-2.0
"""The operator's job commands: job run (and following), job show, jobs."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

from boxmunge import fileutil
from boxmunge.api import actions as api_actions
from boxmunge.api import job_writer
from boxmunge.api import jobs as api_jobs
from boxmunge.api.job_worker import run_job
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Action, Registry
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import INTEGER, obj
from boxmunge.api.worker_identity import WorkerIdentity
from boxmunge.commands import job_cmd
from boxmunge.paths import BoxPaths
from tests.api.fakes import StubHost, read_audit

PROJECT = {"type": "string", "pattern": "[a-z0-9][a-z0-9-]{0,62}"}
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)


def _ok(params, ctx):
    print("backing up", flush=True)
    return {"n": 3}


def _fails(params, ctx):
    raise ActionError(ErrorCode.FAILED, "the dump failed: disk full")


def _registry(handler=_ok) -> Registry:
    registry = Registry()
    registry.register(Action(
        name="project.backup", tier=Tier.OPERATE, summary="Back up a project.",
        params=obj({"project": PROJECT}), result=obj({"n": INTEGER}),
        handler=handler, locks=("project",), job=True, cli="backup"))
    registry.register(Action(
        name="status.get", tier=Tier.OBSERVE, summary="Status.", params=obj({}),
        result=obj({"n": INTEGER}), handler=lambda p, c: {"n": 1}))
    return registry


def _stat(start: int) -> str:
    return f"{os.getpid()} (python) " + " ".join(["S"] + ["0"] * 18 + [str(start)]) + "\n"


@pytest.fixture
def box(paths, tmp_path, monkeypatch):
    """A box with one project, a sealed-style (existing) audit log and a fake
    /proc for the worker run inline."""
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    paths.project_dir("myapp").mkdir(parents=True)
    paths.audit_log.parent.mkdir(parents=True, exist_ok=True)
    paths.audit_log.touch()
    proc = tmp_path / "proc"
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text("boot-1\n")
    (proc / str(os.getpid())).mkdir()
    (proc / str(os.getpid()) / "stat").write_text(_stat(777))
    monkeypatch.setattr(fileutil, "LOCK_POLL_SECONDS", 0.05)
    monkeypatch.setattr(job_cmd, "running_as_root", lambda: False)
    paths.proc = proc
    return paths


def _use(monkeypatch, registry: Registry) -> None:
    monkeypatch.setattr(api_actions, "build_registry", lambda: registry)


def _queued_id(paths) -> str:
    [path] = paths.jobs_queue.glob("*.json")
    return path.stem


class _Runner:
    """Stands in for the job runner: the follower's first sleep runs the
    queued job inline, after *idle* sleeps that only advance the clock."""

    def __init__(self, paths, registry, monkeypatch, *, idle: int = 0) -> None:
        self.paths, self.registry, self.idle = paths, registry, idle
        self.clock = 0.0
        self.sleeps = 0
        monkeypatch.setattr(job_cmd, "_sleep", self.sleep)
        monkeypatch.setattr(job_cmd, "_monotonic", lambda: self.clock)

    def sleep(self, seconds: float) -> None:
        assert seconds == job_cmd.FOLLOW_POLL_SECONDS
        self.sleeps += 1
        self.clock += seconds
        if self.sleeps == self.idle + 1:
            assert run_job(self.paths, _queued_id(self.paths), self.registry, StubHost(),
                           proc=self.paths.proc) == 0
        assert self.sleeps < 1000, "the follower never saw the job finish"


def _exit_code(call) -> int:
    with pytest.raises(SystemExit) as exc:
        call()
    return exc.value.code


def test_job_run_follows_to_success_and_exits_0(box, monkeypatch, capsys):
    registry = _registry()
    _use(monkeypatch, registry)
    _Runner(box, registry, monkeypatch)
    code = _exit_code(lambda: job_cmd.cmd_job(["run", "project.backup",
                                               '{"project":"myapp"}']))
    out = capsys.readouterr().out
    assert code == 0
    job_id = (list(box.jobs_dir.glob("*.json")))[0].stem
    lines = out.splitlines()
    assert lines[0] == f"job {job_id} queued"
    assert "backing up" in lines
    assert lines[-2:] == [f"job {job_id} succeeded", 'result: {"n": 3}']
    accepted = [r for r in read_audit(box) if r["outcome"] == "accepted"]
    assert [(r["principal"], r["job"]) for r in accepted] == [("operator:ssh", job_id)]


def test_job_run_failure_prints_code_and_message_exit_1(box, monkeypatch, capsys):
    registry = _registry(_fails)
    _use(monkeypatch, registry)
    _Runner(box, registry, monkeypatch)
    code = _exit_code(lambda: job_cmd.cmd_job(["run", "project.backup",
                                               '{"project":"myapp"}']))
    captured = capsys.readouterr()
    assert code == 1
    assert "ERROR: failed: the dump failed: disk full" in captured.err


def test_job_run_refusal_prints_the_reason(box, monkeypatch, capsys):
    _use(monkeypatch, _registry())
    code = _exit_code(lambda: job_cmd.cmd_job(["run", "project.backup",
                                               '{"project":"nope"}']))
    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("ERROR: ")
    assert "nope" in captured.err
    assert "queued" not in captured.out
    assert not box.jobs_queue.is_dir() or not list(box.jobs_queue.glob("*.json"))
    assert [r["outcome"] for r in read_audit(box)] == ["refused"]


def test_job_run_invalid_params_lists_every_violation(box, monkeypatch, capsys):
    _use(monkeypatch, _registry())
    code = _exit_code(lambda: job_cmd.cmd_job(["run", "project.backup",
                                               '{"project":"myapp","x":1}']))
    assert code == 1
    err = capsys.readouterr().err
    assert "ERROR: Parameters for project.backup do not match its schema." in err
    assert "\n  - " in err


@pytest.mark.parametrize("argv, says", [
    (["run", "project.backup", "not json"], "not JSON"),
    (["run", "project.backup", "[1]"], "a JSON object"),
    (["run", "nosuch.action"], "unknown action 'nosuch.action'"),
    (["run", "status.get"], "status.get does not run as a job"),
    (["show", "not-an-id"], "not a job id"),
    ([], "needs a subcommand"),
    (["frobnicate"], "unknown job subcommand"),
])
def test_usage_errors_exit_2(box, monkeypatch, capsys, argv, says):
    _use(monkeypatch, _registry())
    assert _exit_code(lambda: job_cmd.cmd_job(argv)) == 2
    assert says in capsys.readouterr().err
    assert read_audit(box) == []


def test_job_run_as_root_is_the_supervisor_principal(box, monkeypatch, capsys):
    _use(monkeypatch, _registry())
    monkeypatch.setattr(job_cmd, "running_as_root", lambda: True)
    job_cmd.cmd_job(["run", "project.backup", '{"project":"myapp"}', "--detach"])
    job_id = _queued_id(box)
    record = json.loads((box.jobs_queue / f"{job_id}.json").read_text())
    assert record["principal"] == "operator:supervisor"
    assert capsys.readouterr().out.splitlines() == [
        f"job {job_id} queued", f"follow it with: boxmunge job show {job_id} --events"]


def test_still_queued_hint_printed_once(box, monkeypatch, capsys):
    registry = _registry()
    _use(monkeypatch, registry)
    runner = _Runner(box, registry, monkeypatch, idle=45)
    code = _exit_code(lambda: job_cmd.cmd_job(["run", "project.backup",
                                               '{"project":"myapp"}']))
    assert code == 0
    assert runner.sleeps == 46
    err = capsys.readouterr().err
    assert err.count(job_cmd.QUEUED_HINT) == 1
    assert job_cmd.QUEUED_HINT == ("still queued after 30 s: is the job runner active? "
                                   "systemctl status boxmunge-jobs.path")


def test_ctrl_c_leaves_the_job_running_and_exits_130(box, monkeypatch, capsys):
    _use(monkeypatch, _registry())

    def interrupt(_seconds):
        raise KeyboardInterrupt
    monkeypatch.setattr(job_cmd, "_sleep", interrupt)
    code = _exit_code(lambda: job_cmd.cmd_job(["run", "project.backup",
                                               '{"project":"myapp"}']))
    job_id = _queued_id(box)
    assert code == 130
    assert (f"the job keeps running; follow it with: boxmunge job show {job_id} --events"
            in capsys.readouterr().err)


def _jobs_in_every_state(paths) -> dict[str, str]:
    ids = {"queued": "01J" + "A" * 23, "running": "01J" + "B" * 23,
           "succeeded": "01J" + "C" * 23}
    for n, job_id in enumerate(ids.values()):
        record = job_writer.new_record(job_id, "project.backup", {"project": "myapp"},
                                       "operator:ssh", "myapp", NOW.replace(minute=n))
        assert job_writer.publish(paths, record)
    worker = WorkerIdentity("boot-1", os.getpid(), 777)
    for job_id in (ids["running"], ids["succeeded"]):
        assert job_writer.claim(paths, job_id, worker, NOW) is not None
    job_writer.finish(paths, ids["succeeded"], state="succeeded", error=None,
                      result={"n": 1}, now=NOW, result_schemas=_registry_results)
    return ids


def _registry_results(name):
    return {"project.backup": obj({"n": INTEGER})}.get(name)


def test_jobs_running_lists_only_unfinished(box, monkeypatch, capsys):
    _use(monkeypatch, _registry())
    monkeypatch.setattr(api_jobs, "is_alive", lambda _worker, _proc: True)
    ids = _jobs_in_every_state(box)
    job_cmd.cmd_jobs(["--running", "--json"])
    listed = json.loads(capsys.readouterr().out)
    assert [j["id"] for j in listed["jobs"]] == [ids["running"], ids["queued"]]
    job_cmd.cmd_jobs([])
    table = capsys.readouterr().out
    assert all(job_id in table for job_id in ids.values())
    job_cmd.cmd_jobs(["--running"])
    table = capsys.readouterr().out
    assert ids["succeeded"] not in table and ids["running"] in table


def test_jobs_reports_an_unreadable_record_and_exits_1(box, monkeypatch, capsys):
    _use(monkeypatch, _registry())
    box.jobs_dir.mkdir(parents=True, exist_ok=True)
    (box.jobs_dir / ("01J" + "D" * 23 + ".json")).write_text("{not json")
    assert _exit_code(lambda: job_cmd.cmd_jobs([])) == 1
    assert "WARNING: job 01J" in capsys.readouterr().err


def test_job_show_prints_the_record_and_events(box, monkeypatch, capsys):
    registry = _registry()
    _use(monkeypatch, registry)
    _Runner(box, registry, monkeypatch)
    _exit_code(lambda: job_cmd.cmd_job(["run", "project.backup", '{"project":"myapp"}']))
    job_id = list(box.jobs_dir.glob("*.json"))[0].stem
    capsys.readouterr()
    job_cmd.cmd_job(["show", job_id, "--events"])
    out = capsys.readouterr().out
    assert f"job {job_id}  project.backup  succeeded" in out
    assert "backing up" in out
    job_cmd.cmd_job(["show", job_id, "--json", "--events"])
    shown = json.loads(capsys.readouterr().out)
    assert shown["job"]["state"] == "succeeded" and shown["events"]


def test_job_show_unknown_job_exits_1(box, monkeypatch, capsys):
    _use(monkeypatch, _registry())
    assert _exit_code(lambda: job_cmd.cmd_job(["show", "01J" + "E" * 23])) == 1
    assert "boxmunge jobs" in capsys.readouterr().err
