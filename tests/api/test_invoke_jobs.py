# SPDX-License-Identifier: Apache-2.0
"""invoke() with a job runner: a job action is published, not run."""
from __future__ import annotations

import fcntl
import json
import os
import stat

import pytest

from boxmunge import fileutil, fs_nofollow
from boxmunge.api import invoke as invoke_mod
from boxmunge.api import job_writer
from boxmunge.api.audit import AuditLog
from boxmunge.api.invoke import Invoker
from boxmunge.api.job_gate import UPGRADE_REFUSAL
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.registry import Action, Registry
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import BOOLEAN, obj
from boxmunge.api.timefmt import format_utc
from boxmunge.fileutil import open_shared_lockfile
from boxmunge.state import StateError
from tests.api.fakes import StubHost, read_audit

PROJECT = {"type": "string", "pattern": "[a-z0-9][a-z0-9-]{0,62}"}
OPERATOR = Principal.operator()


def _never_run(params, ctx):
    raise AssertionError("a job action's handler never runs in invoke")


def _registry() -> Registry:
    registry = Registry()
    registry.register(Action(
        name="project.stage", tier=Tier.OPERATE, summary="Stage a release.",
        params=obj({"project": PROJECT}), result=obj({"ok": BOOLEAN}),
        handler=_never_run, job=True, locks=("project",)))
    return registry


def _invoker(paths, audit: AuditLog | None = None) -> Invoker:
    return Invoker(_registry(), paths, StubHost(),
                   audit or AuditLog(paths.audit_log, create=True), jobs=True)


@pytest.fixture
def shop(paths):
    paths.project_dir("shop").mkdir(parents=True)
    return paths


def _queued(paths) -> list[str]:
    if not paths.jobs_queue.is_dir():
        return []
    return sorted(p.name for p in paths.jobs_queue.iterdir())


def test_job_action_publishes_a_queued_record_and_returns_it(shop) -> None:
    result = _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert result.job is True and result.action == "project.stage"
    record = result.data
    assert (record["state"], record["action"], record["project"]) == \
        ("queued", "project.stage", "shop")
    assert record["principal"] == OPERATOR.id
    assert json.loads(record["params"]) == {"project": "shop"}
    on_disk = json.loads((shop.jobs_queue / f"{record['id']}.json").read_text())
    assert on_disk == record
    audit = read_audit(shop)
    assert [(r["outcome"], r.get("job")) for r in audit] == [("accepted", record["id"])]


def test_invoke_takes_no_project_lock_for_a_job(shop) -> None:
    with fileutil.project_lock("shop", shop):
        result = _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert result.job is True


def test_accepted_record_names_the_job_before_publish(shop, monkeypatch) -> None:
    seen = []

    def publish(paths, record):
        last = read_audit(paths)[-1]
        assert (last["outcome"], last["job"]) == ("accepted", record["id"])
        seen.append(record["id"])
        return job_writer.publish(paths, record)

    monkeypatch.setattr(invoke_mod, "publish", publish)
    result = _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert seen == [result.data["id"]]


def test_unwritable_audit_publishes_nothing(shop) -> None:
    audit = AuditLog(shop.root / "no-such-dir" / "audit.jsonl", create=False)
    with pytest.raises(ActionError) as excinfo:
        _invoker(shop, audit).invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert excinfo.value.code is ErrorCode.UNAVAILABLE
    assert "did not run" in excinfo.value.message
    assert _queued(shop) == []


def test_upgrade_holding_the_gate_refuses_with_why_and_when(shop) -> None:
    fd = open_shared_lockfile(shop.jobs_gate)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(ActionError) as excinfo:
            _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR)
    finally:
        os.close(fd)
    assert excinfo.value.code is ErrorCode.UNAVAILABLE
    assert excinfo.value.message == UPGRADE_REFUSAL
    assert _queued(shop) == []
    [record] = read_audit(shop)
    assert (record["outcome"], record["code"], record["message"]) == \
        ("refused", "unavailable", UPGRADE_REFUSAL)


def test_unknown_project_is_not_found_before_publish(paths, monkeypatch) -> None:
    monkeypatch.setattr(invoke_mod, "upgrade_holds_gate",
                        lambda p: pytest.fail("the gate is checked after the project"))
    with pytest.raises(ActionError) as excinfo:
        _invoker(paths).invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert excinfo.value.code is ErrorCode.NOT_FOUND
    assert _queued(paths) == []
    [record] = read_audit(paths)
    assert (record["outcome"], record["code"]) == ("refused", "not_found")


def test_publish_prunes_old_jobs(shop, monkeypatch) -> None:
    calls = []

    def prune(paths, now):
        assert _queued(paths) == [], "prune runs before the new job is published"
        assert [r["outcome"] for r in read_audit(paths)] == ["accepted"], \
            "prune runs after the accepted record"
        calls.append((paths, now))
        return []

    monkeypatch.setattr(invoke_mod, "prune", prune)
    result = _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR)
    [(pruned_paths, now)] = calls
    assert pruned_paths is shop
    assert result.data["created_at"] == format_utc(now)


def test_publish_failure_is_audited_failed_and_unavailable(shop, monkeypatch) -> None:
    def publish(paths, record):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(invoke_mod, "publish", publish)
    with pytest.raises(ActionError) as excinfo:
        _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert excinfo.value.code is ErrorCode.UNAVAILABLE
    assert "No space left on device" in excinfo.value.message
    accepted, failed = read_audit(shop)
    assert accepted["outcome"] == "accepted" and failed["outcome"] == "failed"
    assert failed["job"] == accepted["job"] and failed["code"] == "unavailable"


def test_prune_failure_is_audited_failed_and_queues_nothing(shop, monkeypatch) -> None:
    def prune(paths, now):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(invoke_mod, "prune", prune)
    with pytest.raises(ActionError) as excinfo:
        _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert excinfo.value.code is ErrorCode.UNAVAILABLE
    assert f"pruning old jobs in {shop.jobs_dir} failed" in excinfo.value.message
    assert _queued(shop) == []
    accepted, failed = read_audit(shop)
    assert (accepted["outcome"], failed["outcome"]) == ("accepted", "failed")
    assert failed["job"] == accepted["job"]


def test_publish_failing_after_its_link_queues_nothing_and_says_so(shop, monkeypatch) -> None:
    real = job_writer.fsync_dir

    def fsync_dir(path):
        if path == shop.jobs_queue:
            raise OSError(5, "Input/output error")
        real(path)

    monkeypatch.setattr(job_writer, "fsync_dir", fsync_dir)
    with pytest.raises(ActionError) as excinfo:
        _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert excinfo.value.code is ErrorCode.UNAVAILABLE
    assert "writing the queued record" in excinfo.value.message
    assert _queued(shop) == []
    assert [r["outcome"] for r in read_audit(shop)] == ["accepted", "failed"]


def test_publish_state_error_reaches_the_client_as_failed(shop, monkeypatch) -> None:
    def publish(paths, record):
        raise StateError("queue/x.json appeared; inspect it")

    monkeypatch.setattr(invoke_mod, "publish", publish)
    with pytest.raises(ActionError) as excinfo:
        _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert excinfo.value.code is ErrorCode.FAILED
    assert excinfo.value.message == "queue/x.json appeared; inspect it"
    assert read_audit(shop)[-1]["message"] == "queue/x.json appeared; inspect it"


def test_a_taken_job_id_is_a_reported_bug(shop, monkeypatch) -> None:
    monkeypatch.setattr(invoke_mod, "publish", lambda paths, record: False)
    with pytest.raises(ActionError) as excinfo:
        _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert excinfo.value.code is ErrorCode.FAILED
    assert "already taken" in excinfo.value.message and "bug" in excinfo.value.message
    accepted, failed = read_audit(shop)
    assert failed["outcome"] == "failed" and failed["job"] == accepted["job"]


def test_job_actions_without_a_runner_are_still_refused(shop) -> None:
    invoker = Invoker(_registry(), shop, StubHost(), AuditLog(shop.audit_log, create=True))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("project.stage", {"project": "shop"}, OPERATOR)
    assert excinfo.value.code is ErrorCode.UNAVAILABLE
    assert _queued(shop) == []


def test_publish_as_root_leaves_deploy_owned_files(shop, monkeypatch) -> None:
    """Review focus 5: an operator running the publish as root must leave
    every file it creates deploy-owned and deploy-readable."""
    monkeypatch.setattr(fs_nofollow, "running_as_root", lambda: True)
    monkeypatch.setattr(fs_nofollow, "deploy_ids", lambda: (os.getuid(), os.getgid()))
    files: list[tuple[str, int]] = []
    dirs: list[str] = []
    real_fchown, real_chown = fs_nofollow.fchown_deploy, fs_nofollow._chown_deploy

    def fchown(fd, what):
        files.append((what, os.fstat(fd).st_ino))
        real_fchown(fd, what)

    def chown(path):
        dirs.append(path)
        real_chown(path)

    for module in (job_writer, fileutil):
        monkeypatch.setattr(module, "fchown_deploy", fchown)
    monkeypatch.setattr(fs_nofollow, "_chown_deploy", chown)

    record = _invoker(shop).invoke("project.stage", {"project": "shop"}, OPERATOR).data
    job_id = record["id"]
    queued = shop.jobs_queue / f"{job_id}.json"
    chowned_inodes = {ino for _, ino in files}
    for path in (queued, shop.job_lock(job_id), shop.jobs_gate):
        assert path.stat().st_ino in chowned_inodes, f"{path} was not handed to deploy"
    temps = [what for what, _ in files if os.path.basename(what).startswith(f".{job_id}.")]
    assert temps and all(what.endswith(".tmp") for what in temps)
    assert {str(shop.jobs_dir), str(shop.jobs_queue)} <= set(dirs)
    assert stat.S_IMODE(queued.stat().st_mode) == 0o640
    for lock in (shop.job_lock(job_id), shop.jobs_gate):
        assert stat.S_IMODE(lock.stat().st_mode) == 0o660
    assert sorted(p.name for p in shop.jobs_dir.iterdir()
                  if p.name.endswith(".tmp")) == []
