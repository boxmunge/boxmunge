# SPDX-License-Identifier: Apache-2.0
"""A job end to end: invoke publishes it, the runner starts its worker, the
worker runs it and records the outcome; and the three crash points between
those steps (after publish, after claim, mid-finish) each recover as the
recovery table says: run once, lost and never re-run, or the move completed."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from boxmunge.api import job_failure, job_runner, job_worker
from boxmunge.api.actions import build_registry
from boxmunge.api.audit import AuditLog
from boxmunge.api.invoke import Invoker
from boxmunge.api.job_runner import run_runner
from boxmunge.api.job_worker import run_job
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.registry import Action, Registry
from boxmunge.api.schema import INTEGER, obj
from boxmunge.api.worker_identity import WorkerIdentity
from boxmunge.project_registry import add_project
from tests.api.fakes import StubHost, read_audit
from tests.bundle_helpers import place_bundle
from tests.stage_helpers import V1, staging_docker_off
from tests.txn_helpers import crash_at

PROJECT = {"type": "string", "pattern": "[a-z0-9][a-z0-9-]{0,62}"}
OPERATOR = Principal.operator("ssh")
CRASHED = 137


class _Exited:
    """A worker the fake spawn already ran to its exit code."""

    def __init__(self, code: int) -> None:
        self._code = code

    def wait(self) -> int:
        return self._code


@pytest.fixture
def box(paths, monkeypatch):
    """A box with an empty audit log, one registered project and alerts
    collected. A worker's identity is its own pid; only this test process
    counts as alive, so a forked worker that crashed is gone."""
    paths.audit_log.parent.mkdir(parents=True, exist_ok=True)
    paths.audit_log.touch()
    add_project("myapp", paths)
    paths.project_dir("myapp").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(job_worker, "current",
                        lambda _proc: WorkerIdentity("boot-1", os.getpid(), 1))
    alerts: list[dict] = []

    def collect(_paths, title, body, **kw):
        alerts.append({"title": title, "body": body, **kw})
        return True

    monkeypatch.setattr(job_worker, "notify", collect)
    monkeypatch.setattr(job_runner, "notify", collect)
    monkeypatch.setattr(job_failure, "notify", collect)
    paths.alerts = alerts
    return paths


def _invoker(paths, registry: Registry) -> Invoker:
    return Invoker(registry, paths, StubHost(), AuditLog(paths.audit_log, create=False),
                   jobs=True)


def _run_runner(paths, registry: Registry) -> list[str]:
    """Run the runner in-process, each worker inline; the ids it started."""
    spawned: list[str] = []

    def spawn(job_id: str) -> _Exited:
        spawned.append(job_id)
        return _Exited(run_job(paths, job_id, registry, StubHost()))

    assert run_runner(paths, spawn=spawn,
                      alive=lambda identity: identity.pid == os.getpid()) == 0
    return spawned


def _only_job(paths) -> str:
    names = [p.name for p in paths.jobs_dir.glob("*.json")]
    names += [p.name for p in paths.jobs_queue.glob("*.json")]
    ids = {n.removesuffix(".json") for n in names}
    assert len(ids) == 1, ids
    return ids.pop()


def _record(paths, job_id: str) -> dict:
    return json.loads((paths.jobs_dir / f"{job_id}.json").read_text())


def _events(paths, job_id: str) -> list[dict]:
    text = (paths.jobs_dir / f"{job_id}.events.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines()]


def _outcomes(paths, job_id: str) -> list[str]:
    return [r["outcome"] for r in read_audit(paths) if r.get("job") == job_id]


def _queue_is_empty(paths) -> bool:
    return list(paths.jobs_queue.iterdir()) == []


def _no_temps(paths) -> bool:
    return list(paths.jobs_dir.glob(".*.tmp")) == []


def test_operator_deploy_job_end_to_end(box) -> None:
    registry = build_registry()
    place_bundle(box, timestamp=V1, files={"VERSION": "v1\n"})
    result = _invoker(box, registry).invoke("project.deploy", {"project": "myapp", "ref": V1},
                                            OPERATOR)
    assert result.job is True and result.data["state"] == "queued"
    job_id = result.data["id"]
    with staging_docker_off():
        assert _run_runner(box, registry) == [job_id]
    record = _record(box, job_id)
    assert (record["state"], record["error"], record["principal"]) == \
        ("succeeded", None, "operator:ssh")
    assert (box.project_dir("myapp") / "VERSION").read_text() == "v1\n"
    events = _events(box, job_id)
    printed = "\n".join(e["message"] for e in events if e["type"] == "log")
    assert "Deploying myapp" in printed
    assert [e["state"] for e in events if e["type"] == "state"][-1] == "succeeded"
    assert _outcomes(box, job_id) == ["accepted", "succeeded"]
    assert _queue_is_empty(box) and _no_temps(box)
    assert box.alerts == []


class _Counted:
    """An operate job's handler that counts its runs in a file, so a run in
    a forked worker is counted too."""

    def __init__(self, tmp: Path) -> None:
        self.file = tmp / "runs"

    def __call__(self, params, ctx):
        runs = self.runs + 1
        self.file.write_text(str(runs))
        print(f"run {runs}", flush=True)
        return {"n": runs}

    @property
    def runs(self) -> int:
        return int(self.file.read_text()) if self.file.exists() else 0


def _counted_registry(handler: _Counted) -> Registry:
    registry = Registry()
    registry.register(Action(
        name="project.backup", tier=Tier.OPERATE, summary="Back up a project.",
        params=obj({"project": PROJECT}), result=obj({"n": INTEGER}),
        handler=handler, locks=("project",), job=True, cli="backup"))
    return registry


@pytest.fixture
def counted(box, tmp_path):
    handler = _Counted(tmp_path)
    return handler, _counted_registry(handler)


def _invoke_backup(paths, registry: Registry):
    return _invoker(paths, registry).invoke("project.backup", {"project": "myapp"}, OPERATOR)


def test_crash_after_publish_runs_once(box, counted) -> None:
    handler, registry = counted
    assert crash_at("job.published", lambda: _invoke_backup(box, registry)) == CRASHED
    job_id = _only_job(box)
    assert (box.jobs_queue / f"{job_id}.json").exists()
    assert not _no_temps(box)  # the crash left publish's temp behind
    assert _run_runner(box, registry) == [job_id]
    assert _run_runner(box, registry) == []
    assert handler.runs == 1
    assert _record(box, job_id)["state"] == "succeeded"
    assert _outcomes(box, job_id) == ["accepted", "succeeded"]
    assert _queue_is_empty(box) and _no_temps(box)


def test_crash_after_claim_is_lost_not_rerun(box, counted) -> None:
    handler, registry = counted
    job_id = _invoke_backup(box, registry).data["id"]
    code = crash_at("job.claimed", lambda: run_job(box, job_id, registry, StubHost()))
    assert code == CRASHED
    queued = json.loads((box.jobs_queue / f"{job_id}.json").read_text())
    assert queued["state"] == "running" and queued["worker"]["pid"] != os.getpid()
    assert _run_runner(box, registry) == []
    assert handler.runs == 0
    record = _record(box, job_id)
    assert (record["state"], record["error"]["code"]) == ("failed", "worker_lost")
    assert "backup myapp" in record["error"]["message"]
    assert _outcomes(box, job_id) == ["accepted", "failed"]
    assert [a["title"] for a in box.alerts] == [
        f"boxmunge: job {job_id} (project.backup myapp) was cut off"]
    assert _queue_is_empty(box)


def test_crash_during_finish_completes_the_move(box, counted) -> None:
    handler, registry = counted
    job_id = _invoke_backup(box, registry).data["id"]
    code = crash_at("job.moving", lambda: run_job(box, job_id, registry, StubHost()))
    assert code == CRASHED
    queued, done = box.jobs_queue / f"{job_id}.json", box.jobs_dir / f"{job_id}.json"
    assert os.path.samefile(queued, done)  # one file under both names
    assert _run_runner(box, registry) == []
    assert handler.runs == 1
    record = _record(box, job_id)
    assert (record["state"], record["result"]) == ("succeeded", {"n": 1})
    assert _outcomes(box, job_id) == ["accepted", "succeeded"]  # recovered by the runner
    recovered = [r for r in read_audit(box) if r.get("job") == job_id][-1]
    assert (recovered["principal"], recovered["action"], recovered["params"]) == \
        ("operator:ssh", "project.backup", None)
    assert _run_runner(box, registry) == []
    assert _outcomes(box, job_id) == ["accepted", "succeeded"]  # once
    assert _queue_is_empty(box) and box.alerts == []


def test_upgrade_notes_validate() -> None:
    """The 0.12.0 entries (the job notes among them) compile."""
    from boxmunge.upgrade_notes import load_entry_file
    repo = Path(__file__).resolve().parents[2]
    entries = load_entry_file(repo / "upgrade-notes" / "0.12.0.json")
    ids = {e.id for e in entries.entries}
    assert {"0.12.0-operate-jobs", "0.12.0-upgrade-waits-for-jobs",
            "0.12.0-audit-append-only"} <= ids
