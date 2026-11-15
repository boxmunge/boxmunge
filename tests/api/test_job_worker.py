# SPDX-License-Identifier: Apache-2.0
"""The job worker: claim, bounded lock wait, captured output, one outcome."""
from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from boxmunge import fileutil
from boxmunge.api import job_capture, job_gate, job_worker, job_writer
from boxmunge.api.job_capture import CoreFailed
from boxmunge.api.job_worker import EX_TEMPFAIL, run_job
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Action, Registry
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import INTEGER, obj
from boxmunge.fileutil import project_lock
from boxmunge.termination import Terminated, sigterm_unwinds
from tests.api.fakes import StubHost, read_audit

JOB_ID = "01J" + "A" * 23
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
PROJECT = {"type": "string", "pattern": "[a-z0-9][a-z0-9-]{0,62}"}
HOLDER = "pid 4242: boxmunge backup myapp"


class Handler:
    """An operate job's handler: records each call, prints, and runs a
    subprocess echo, then does whatever the test asks."""

    def __init__(self, then=None, result=None) -> None:
        self.calls: list[dict] = []
        self.ctxs: list = []
        self._then = then
        self._result = {"n": 1} if result is None else result

    def __call__(self, params, ctx):
        self.calls.append(params)
        self.ctxs.append(ctx)
        print("hello from the handler", flush=True)
        subprocess.run(["echo", "hello from a child"], check=True)
        if self._then is not None:
            self._then(params, ctx)
        return self._result


def _registry(handler, *, params=None) -> Registry:
    registry = Registry()
    registry.register(Action(
        name="project.backup", tier=Tier.OPERATE, summary="Back up a project.",
        params=params or obj({"project": PROJECT}), result=obj({"n": INTEGER}),
        handler=handler, locks=("project",), job=True, cli="backup"))
    return registry


def _stat(start: int) -> str:
    return f"{os.getpid()} (python) " + " ".join(["S"] + ["0"] * 18 + [str(start)]) + "\n"


@pytest.fixture
def box(paths, tmp_path, monkeypatch):
    """A box with an empty audit log, a fake /proc for this process, and
    lock holders and alerts faked (no /proc/locks, no Pushover)."""
    proc = tmp_path / "proc"
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text("boot-1\n")
    (proc / str(os.getpid())).mkdir()
    (proc / str(os.getpid()) / "stat").write_text(_stat(777))
    paths.audit_log.touch()
    monkeypatch.setattr(fileutil, "lock_holder", lambda _p: HOLDER)
    monkeypatch.setattr(fileutil, "LOCK_POLL_SECONDS", 0.05)
    alerts: list[dict] = []
    monkeypatch.setattr(job_worker, "notify",
                        lambda _paths, title, body, **kw: alerts.append(
                            {"title": title, "body": body, **kw}) or True)
    paths.proc = proc
    paths.alerts = alerts
    return paths


def _publish(paths, params=None) -> None:
    record = job_writer.new_record(JOB_ID, "project.backup", params or {"project": "myapp"},
                                   "operator:ssh", "myapp", NOW)
    assert job_writer.publish(paths, record)


def _run(paths, handler, **kw) -> int:
    return run_job(paths, JOB_ID, kw.pop("registry", None) or _registry(handler),
                   StubHost(), proc=paths.proc)


def _record(paths) -> dict:
    done = paths.jobs_dir / f"{JOB_ID}.json"
    path = done if done.exists() else paths.jobs_queue / f"{JOB_ID}.json"
    return json.loads(path.read_text())


def _events(paths) -> list[dict]:
    text = (paths.jobs_dir / f"{JOB_ID}.events.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines()]


def _logs(paths) -> list[str]:
    return [e["message"] for e in _events(paths) if e["type"] == "log"]


def _outcomes(paths) -> list[dict]:
    return [r for r in read_audit(paths) if r["outcome"] in ("succeeded", "failed")]


def _hold_lock(paths, seconds: float) -> threading.Thread:
    held = threading.Event()

    def hold() -> None:
        with project_lock("myapp", paths):
            held.set()
            time.sleep(seconds)

    thread = threading.Thread(target=hold)
    thread.start()
    assert held.wait(5)
    return thread


def test_runs_a_queued_job_to_succeeded_with_log_events_and_outcome_audit(box):
    _publish(box)
    handler = Handler()
    assert _run(box, handler) == 0
    record = _record(box)
    assert (record["state"], record["result"], record["error"]) == ("succeeded", {"n": 1}, None)
    assert not (box.jobs_queue / f"{JOB_ID}.json").exists()
    assert handler.calls == [{"project": "myapp"}]
    events = _events(box)
    assert [e["state"] for e in events if e["type"] == "state"] == ["running", "succeeded"]
    assert "hello from the handler" in _logs(box)
    assert "hello from a child" in _logs(box)
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    [outcome] = _outcomes(box)
    assert outcome["outcome"] == "succeeded"
    assert (outcome["job"], outcome["principal"], outcome["action"]) == (
        JOB_ID, "operator:ssh", "project.backup")
    assert outcome["params"] == {"project": "myapp"}


def test_claim_is_synced_before_the_handler_runs(box, monkeypatch):
    _publish(box)
    order: list[str] = []
    real = job_writer.fsync_dir

    def fsync_dir(path):
        real(path)
        order.append(f"sync {Path(path).name}")
    monkeypatch.setattr(job_writer, "fsync_dir", fsync_dir)
    handler = Handler(then=lambda *_: order.append("handler"))
    assert _run(box, handler) == 0
    assert "handler" in order
    assert "sync queue" in order[:order.index("handler")]


def test_busy_job_never_calls_the_handler_and_names_the_holder(box, monkeypatch):
    monkeypatch.setattr(job_worker, "JOB_LOCK_WAIT_SECONDS", 0.3)
    _publish(box)
    handler = Handler()
    holder = _hold_lock(box, 1.5)
    try:
        assert _run(box, handler) == 0
    finally:
        holder.join()
    error = _record(box)["error"]
    assert error["code"] == "busy"
    assert (f"myapp's lock was held by {HOLDER} for the whole 0.3 seconds this job waited. "
            "Nothing was changed.") in error["message"]
    assert "boxmunge job run project.backup '{\"project\":\"myapp\"}'" in error["message"]
    assert handler.calls == []
    waits = [e for e in _events(box) if e["type"] == "step" and e["step"] == "lock"]
    assert waits[0]["status"] == "started"
    assert f"waiting for myapp's lock, held by {HOLDER}" == waits[0]["message"]
    assert _outcomes(box)[0]["code"] == "busy"


def test_the_lock_wait_is_two_minutes():
    assert job_worker.JOB_LOCK_WAIT_SECONDS == 120


def test_busy_message_names_the_wait_in_minutes(box, monkeypatch):
    monkeypatch.setattr(job_worker, "JOB_LOCK_WAIT_SECONDS", 120)

    def timeout(project, paths, *, timeout, on_wait):
        on_wait(HOLDER)
        raise fileutil.LockWaitTimeout(project, timeout, HOLDER)
    monkeypatch.setattr(job_worker, "project_lock_wait", timeout)
    _publish(box)
    assert _run(box, Handler()) == 0
    assert "for the whole 2 minutes this job waited" in _record(box)["error"]["message"]


def test_waits_for_a_briefly_held_lock_then_runs(box):
    _publish(box)
    handler = Handler()
    holder = _hold_lock(box, 1.5)
    try:
        assert _run(box, handler) == 0
    finally:
        holder.join()
    assert _record(box)["state"] == "succeeded"
    assert len(handler.calls) == 1
    steps = [(e["step"], e["status"]) for e in _events(box) if e["type"] == "step"]
    assert steps == [("lock", "started"), ("lock", "succeeded")]


def test_core_failure_message_uses_error_lines(box):
    def fail(*_):
        print("pulling images")
        print("ERROR: image shop:v2 not found", flush=True)
        subprocess.run(["sh", "-c", "echo 'ERROR: compose up failed'"], check=True)
        raise CoreFailed("backup", 1)
    _publish(box)
    assert _run(box, Handler(then=fail)) == 0
    error = _record(box)["error"]
    assert error["code"] == "failed"
    assert error["message"].startswith("`backup` exited 1: ERROR: image shop:v2 not found / "
                                       "ERROR: compose up failed")
    assert f"boxmunge job show {JOB_ID} --events" in error["message"]


def test_action_error_maps_to_its_code(box):
    def refuse(*_):
        raise ActionError(ErrorCode.CONFLICT, "a release is already staged")
    _publish(box)
    assert _run(box, Handler(then=refuse)) == 0
    assert _record(box)["error"] == {"code": "conflict", "message": "a release is already staged"}


def test_unexpected_exception_is_an_internal_error_and_logged(box, monkeypatch):
    logged: list[str] = []
    monkeypatch.setattr(job_worker, "log_error", lambda c, m, *a, **kw: logged.append(m))

    def crash(*_):
        raise KeyError("slot")
    _publish(box)
    assert _run(box, Handler(then=crash)) == 0
    error = _record(box)["error"]
    assert error["code"] == "failed"
    assert error["message"].startswith("internal error: KeyError")
    assert logged and JOB_ID in logged[0]


def test_result_outside_the_schema_fails(box):
    _publish(box)
    assert _run(box, Handler(result={"n": "many"})) == 0
    record = _record(box)
    assert (record["state"], record["result"]) == ("failed", None)
    assert "does not match its schema" in record["error"]["message"]


def test_params_that_no_longer_validate_fail_without_running(box):
    _publish(box, {"project": "myapp"})
    handler = Handler()
    registry = _registry(handler, params=obj({"project": PROJECT, "reason": PROJECT}))
    assert _run(box, handler, registry=registry) == 0
    error = _record(box)["error"]
    assert error["code"] == "invalid_params"
    assert ("the job's parameters no longer match project.backup (boxmunge changed between "
            "publish and run)") in error["message"]
    assert "run the call again" in error["message"]
    assert handler.calls == []


def test_an_action_no_longer_registered_fails_without_running(box):
    _publish(box)
    assert run_job(box, JOB_ID, Registry(), StubHost(), proc=box.proc) == 0
    error = _record(box)["error"]
    assert error["code"] == "not_found"
    assert "project.backup" in error["message"]


def test_after_release_runs_once_the_lock_is_free(box):
    ran: list[str] = []

    def later() -> None:
        with project_lock("myapp", box):  # raises LockError if still held
            ran.append("after")
        print("after release output", flush=True)

    _publish(box)
    assert _run(box, Handler(then=lambda _p, ctx: ctx.after_release(later))) == 0
    assert ran == ["after"]
    assert "after release output" in _logs(box)


def test_after_release_runs_even_when_the_handler_fails(box):
    ran: list[str] = []

    def fail(_p, ctx):
        ctx.after_release(lambda: ran.append("after"))
        raise CoreFailed("resume", 3)
    _publish(box)
    assert _run(box, Handler(then=fail)) == 0
    assert ran == ["after"]
    assert _record(box)["error"]["code"] == "failed"


def test_handler_steps_reach_the_event_log(box):
    _publish(box)
    emit = lambda _p, ctx: ctx.emit({"step": "pull", "status": "started"})  # noqa: E731
    assert _run(box, Handler(then=emit)) == 0
    assert ("pull", "started") in [(e["step"], e["status"]) for e in _events(box)
                                   if e["type"] == "step"]


def _hold_gate_exclusively(paths) -> int:
    fd = fileutil.open_shared_lockfile(paths.jobs_gate)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def test_worker_that_waited_for_the_gate_exits_tempfail_leaving_the_job_queued(
        box, monkeypatch):
    monkeypatch.setattr(job_gate, "GATE_POLL_SECONDS", 0.05)
    _publish(box)
    fd = _hold_gate_exclusively(box)
    threading.Timer(0.3, os.close, (fd,)).start()
    handler = Handler()
    assert _run(box, handler) == EX_TEMPFAIL
    record = _record(box)
    assert (record["state"], record["worker"]) == ("queued", None)
    assert handler.calls == []
    assert not (box.jobs_dir / f"{JOB_ID}.events.jsonl").exists()


def test_gate_held_for_the_whole_wait_exits_tempfail(box, monkeypatch):
    monkeypatch.setattr(job_gate, "UPGRADE_GATE_WAIT_SECONDS", 0)
    _publish(box)
    fd = _hold_gate_exclusively(box)
    try:
        assert _run(box, Handler()) == EX_TEMPFAIL
    finally:
        os.close(fd)
    assert _record(box)["state"] == "queued"


def test_sigterm_mid_handler_fails_the_job_and_alerts_the_way_out(box):
    def stop(*_):
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(5)  # the signal arrives first
    _publish(box)
    with pytest.raises(Terminated), sigterm_unwinds():
        _run(box, Handler(then=stop))
    error = _record(box)["error"]
    assert error["code"] == "failed"
    assert error["message"].startswith(
        "stopped by SIGTERM (a service stop or shutdown); it was not run again")
    assert "boxmunge backup myapp" in error["message"]
    [alert] = box.alerts
    assert alert["priority"] == 1
    assert "boxmunge backup myapp" in alert["body"]
    assert JOB_ID in alert["title"]
    assert _outcomes(box)[0]["outcome"] == "failed"


def test_a_claimed_job_is_never_claimed_twice(box):
    second: list[int] = []
    registry_box: list[Registry] = []

    def again(*_):
        second.append(run_job(box, JOB_ID, registry_box[0], StubHost(), proc=box.proc))
    handler = Handler(then=again)
    registry_box.append(_registry(handler))
    _publish(box)
    assert run_job(box, JOB_ID, registry_box[0], StubHost(), proc=box.proc) == 0
    assert second == [1]
    assert len(handler.calls) == 1
    assert run_job(box, JOB_ID, registry_box[0], StubHost(), proc=box.proc) == 1


def test_a_torn_event_log_fails_the_job_naming_the_file(box):
    _publish(box)
    events = box.jobs_dir / f"{JOB_ID}.events.jsonl"
    events.write_bytes(b'{"seq": 1}\n\0\0\0\0')
    handler = Handler()
    assert _run(box, handler) == 0
    record = _record(box)
    assert record["state"] == "failed"
    assert str(events) in record["error"]["message"]
    assert "Nothing was run" in record["error"]["message"]
    assert handler.calls == []
    assert _outcomes(box)[0]["job"] == JOB_ID


def test_output_cut_off_by_a_lingering_grandchild_is_said(box, monkeypatch):
    monkeypatch.setattr(job_capture, "CAPTURE_DRAIN_SECONDS", 0.3)
    children: list[subprocess.Popen] = []

    def linger(*_):
        children.append(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"]))
    _publish(box)
    try:
        assert _run(box, Handler(then=linger)) == 0
    finally:
        for child in children:
            child.kill()
            child.wait()
    assert _record(box)["state"] == "succeeded"
    assert any("Output was cut off" in m for m in _logs(box))


def test_unwritable_outcome_audit_alerts_and_keeps_the_record(box, monkeypatch):
    logged: list[str] = []
    monkeypatch.setattr(job_worker, "log_error", lambda c, m, *a, **kw: logged.append(m))
    _publish(box)
    box.audit_log.unlink()
    assert _run(box, Handler()) == 0
    assert _record(box)["state"] == "succeeded"
    [alert] = box.alerts
    assert alert["priority"] == 1 and "audit" in alert["title"]
    assert any("outcome" in m for m in logged)


def _main(argv: list[str], monkeypatch) -> int:
    from boxmunge import cli
    monkeypatch.setattr(sys, "argv", ["boxmunge", "_run-job", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


@pytest.mark.parametrize("argv", [[], ["01J-not-a-ulid"], [JOB_ID, JOB_ID]])
def test_run_job_command_takes_exactly_one_job_id(argv, monkeypatch, capsys):
    monkeypatch.setattr(job_worker, "run_job", lambda *a, **kw: pytest.fail("ran"))
    assert _main(argv, monkeypatch) == 2
    assert "ERROR:" in capsys.readouterr().err


def test_run_job_command_exits_with_the_workers_code(paths, monkeypatch):
    from boxmunge.paths import BoxPaths
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    seen: list[str] = []
    monkeypatch.setattr(job_worker, "run_job",
                        lambda _paths, job_id, _reg, _host: seen.append(job_id) or EX_TEMPFAIL)
    assert _main([JOB_ID], monkeypatch) == EX_TEMPFAIL
    assert seen == [JOB_ID]


def test_a_job_whose_principal_cannot_be_rebuilt_fails_without_running(box):
    record = job_writer.new_record(JOB_ID, "project.backup", {"project": "myapp"},
                                   "plugin:webui", "myapp", NOW)
    assert job_writer.publish(box, record)
    handler = Handler()
    assert _run(box, handler) == 0
    error = _record(box)["error"]
    assert "published by plugin:webui" in error["message"]
    assert "Nothing was run" in error["message"]
    assert handler.calls == []


def test_an_agents_job_runs_as_that_agent(box):
    record = job_writer.new_record(JOB_ID, "project.backup", {"project": "myapp"},
                                   "agent:mcp(claude-code)", "myapp", NOW)
    assert job_writer.publish(box, record)
    handler = Handler()
    assert _run(box, handler) == 0
    assert handler.ctxs[0].principal.id == "agent:mcp(claude-code)"


def test_an_agent_job_whose_action_became_govern_only_is_forbidden(box):
    handler = Handler()
    registry = Registry()
    registry.register(Action(
        name="project.backup", tier=Tier.GOVERN, summary="Back up a project.",
        params=obj({"project": PROJECT}), result=obj({"n": INTEGER}),
        handler=handler, locks=("project",), job=True, cli="backup"))
    record = job_writer.new_record(JOB_ID, "project.backup", {"project": "myapp"},
                                   "agent:mcp(claude-code)", "myapp", NOW)
    assert job_writer.publish(box, record)
    assert _run(box, handler, registry=registry) == 0
    error = _record(box)["error"]
    assert error["code"] == "forbidden"
    assert "not open to agents" in error["message"]
    assert "Nothing was run" in error["message"]
    assert handler.calls == []
    assert _outcomes(box)[0]["code"] == "forbidden"


def _lock_wait_raising(error, before=None):
    def fake(project, paths, *, timeout, on_wait):
        if before is not None:
            before()
        on_wait(HOLDER)
        raise error
    return fake


def test_a_lock_step_that_cannot_be_written_keeps_the_job_busy(box, monkeypatch):
    from boxmunge.api.job_events import EventLog
    real = EventLog.step

    def step(self, name, status, message=None):
        if name == "lock":
            raise OSError("No space left on device")
        return real(self, name, status, message)
    monkeypatch.setattr(EventLog, "step", step)
    monkeypatch.setattr(job_worker, "log_error", lambda *a, **kw: None)
    monkeypatch.setattr(job_worker, "project_lock_wait", _lock_wait_raising(
        fileutil.LockWaitTimeout("myapp", 120, HOLDER)))
    _publish(box)
    handler = Handler()
    assert _run(box, handler) == 0
    assert _record(box)["error"]["code"] == "busy"
    assert handler.calls == []


def test_a_lock_that_cannot_be_taken_names_the_cause(box, monkeypatch):
    monkeypatch.setattr(job_worker, "project_lock_wait", _lock_wait_raising(
        PermissionError(13, "Permission denied")))
    _publish(box)
    handler = Handler()
    assert _run(box, handler) == 0
    message = _record(box)["error"]["message"]
    assert message.startswith("myapp's lock could not be taken: PermissionError:")
    assert "Nothing was run" in message and "boxmunge job run project.backup" in message
    assert handler.calls == []


def test_a_failure_outside_the_handler_names_its_real_cause(box, monkeypatch):
    def broken(_on_line):
        raise RuntimeError("capture_output is already active")
    monkeypatch.setattr(job_worker, "capture_output", broken)
    monkeypatch.setattr(job_worker, "log_error", lambda *a, **kw: None)
    _publish(box)
    handler = Handler()
    assert _run(box, handler) == 0
    message = _record(box)["error"]["message"]
    assert message == ("internal error: RuntimeError: capture_output is already active. "
                       "Nothing was run.")
    assert handler.calls == []


def _sigterm() -> None:
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(5)  # the signal arrives first


def test_sigterm_before_the_handler_started_changed_nothing(box, monkeypatch):
    monkeypatch.setattr(job_worker, "project_lock_wait", _lock_wait_raising(
        AssertionError("unreachable"), before=_sigterm))
    _publish(box)
    handler = Handler()
    with pytest.raises(Terminated), sigterm_unwinds():
        _run(box, handler)
    message = _record(box)["error"]["message"]
    assert message.startswith("stopped by SIGTERM (a service stop or shutdown) before it "
                              "started. Nothing was changed; run the same call again: "
                              "boxmunge job run project.backup")
    assert "To recover" not in message
    assert handler.calls == []
    assert box.alerts == []


def test_sigterm_during_after_release_keeps_the_handlers_outcome(box):
    _publish(box)
    handler = Handler(then=lambda _p, ctx: ctx.after_release(_sigterm))
    with pytest.raises(Terminated), sigterm_unwinds():
        _run(box, handler)
    record = _record(box)
    assert (record["state"], record["result"], record["error"]) == ("succeeded", {"n": 1}, None)
    assert any("while its after-release steps ran" in m for m in _logs(box))
    [alert] = box.alerts
    assert "after-release" in alert["body"] and alert["priority"] == 1
    assert _outcomes(box)[0]["outcome"] == "succeeded"
