# SPDX-License-Identifier: Apache-2.0
"""Runtime actions: project.pause, resume, backup, restore (operate) and
project.recover, abandon_install (govern).

Each is a job over a lock-free *_locked core: the job worker holds the
project lock, so a handler that reaches for it fails these tests.
"""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import pytest

import boxmunge.commands.backup_cmd as backup_cmd
import boxmunge.commands.pause_cmd as pause_cmd
import boxmunge.commands.recover_cmd as recover_cmd
import boxmunge.commands.restore as restore
import boxmunge.commands.resume_cmd as resume_cmd
from boxmunge.api.actions import build_registry, operate_runtime
from boxmunge.api.context import ActionContext
from boxmunge.api.job_capture import CoreFailed
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import validate
from boxmunge.commands.deploy import deploy_locked
from boxmunge.pause import awaiting_deploy, is_paused, mark_pause_complete, write_paused_state
from boxmunge.project_registry import add_project
from boxmunge.release_txn import load_txn
from boxmunge.state import read_state, write_state
from tests.api.fakes import StubHost, make_invoker, registry_results
from tests.bundle_helpers import place_bundle
from tests.stage_helpers import V1, V2
from tests.test_commands.test_restore_cmd import _setup_project
from tests.test_lifecycle_locks import _setup
from tests.txn_helpers import docker_off

NAME = "myapp"
REGISTRY = build_registry()
CLIS = {
    "project.pause": "pause", "project.resume": "resume", "project.backup": "backup",
    "project.restore": "restore", "project.recover": "recover",
    "project.abandon_install": "prod-deploy",
}
CORES = {
    "project.pause": "pause_locked", "project.resume": "resume_locked",
    "project.backup": "snapshot_locked", "project.restore": "restore_locked",
    "project.recover": "recover_locked", "project.abandon_install": "abandon_locked",
}
GOVERN = ("project.recover", "project.abandon_install")


def _ctx(paths, released: list | None = None) -> ActionContext:
    return ActionContext(principal=Principal.operator(), paths=paths, host=StubHost(),
                         result_schemas=registry_results,
                         after_release=None if released is None else released.append)


def _run(paths, name: str, released: list | None = None, **params) -> dict:
    action = REGISTRY.get(name)
    params = {"project": NAME, **params}
    assert validate(action.params, params) == []
    data = action.handler(params, _ctx(paths, [] if released is None else released))
    assert validate(action.result, data, result_schemas=registry_results) == []
    return data


def _resume_patches(stack: ExitStack, smoke=(True, "")) -> None:
    for target in ("compose_pull", "caddy_reload", "prepare_caddy_config",
                   "prepare_compose_override", "release_restart_policies"):
        stack.enter_context(patch.object(resume_cmd, target))
    stack.enter_context(patch("boxmunge.compose_guard.compose_up"))
    stack.enter_context(patch.object(resume_cmd, "run_smoke", return_value=smoke))


def _pause_case(tmp_path, paths, stack):
    paths = _setup(tmp_path)
    for target in ("caddy_reload", "compose_stop", "hold_restart_policies"):
        stack.enter_context(patch.object(pause_cmd, target))
    return paths, {}, lambda: is_paused(NAME, paths)


def _resume_case(tmp_path, paths, stack):
    paths = _setup(tmp_path)
    write_paused_state(NAME, paths)
    _resume_patches(stack)
    return paths, {}, lambda: not is_paused(NAME, paths)


def _backup_case(tmp_path, paths, stack):
    _setup_project(paths)
    snap = paths.project_backups(NAME) / f"{NAME}-2026-11-15T020000.tar.gz.age"
    inner = stack.enter_context(patch.object(
        backup_cmd, "_run_backup_inner", return_value=backup_cmd.BackupResult(0, snapshot=snap)))
    return paths, {"snapshot": snap.name}, lambda: inner.call_count == 1


def _restore_case(tmp_path, paths, stack):
    _setup_project(paths)
    inner = stack.enter_context(patch.object(restore, "_run_restore_inner", return_value=0))
    return paths, {}, lambda: inner.call_count == 1


def _recover_case(tmp_path, paths, stack):
    paths = _setup(tmp_path)
    write_state(paths.project_health_state(NAME), {"status": "critical_stopped"})
    stack.enter_context(patch("boxmunge.compose_guard.compose_up"))
    for target in ("caddy_reload", "prepare_caddy_config", "prepare_compose_override"):
        stack.enter_context(patch.object(recover_cmd, target))
    stack.enter_context(patch.object(recover_cmd, "run_smoke", return_value=(True, "")))
    return paths, {}, lambda: read_state(paths.project_health_state(NAME))["status"] == "ok"


def _abandon_case(tmp_path, paths, stack):
    """v1 deployed, then v2's install fails before its hook: abandonable."""
    add_project(NAME, paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with docker_off():
        assert deploy_locked(NAME, paths, ref=V1) == 0
        with patch("boxmunge.commands.deploy_tree.install_release",
                   side_effect=OSError("disk full")):
            assert deploy_locked(NAME, paths, ref=V2) == 1
    assert load_txn(paths, NAME) is not None
    return paths, {}, lambda: load_txn(paths, NAME) is None and (
        paths.project_dir(NAME) / "VERSION").read_text() == "v1\n"


CASES = {
    "project.pause": _pause_case, "project.resume": _resume_case,
    "project.backup": _backup_case, "project.restore": _restore_case,
    "project.recover": _recover_case, "project.abandon_install": _abandon_case,
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_each_runtime_handler_runs_its_core_with_the_lock_patched_to_raise(
        tmp_path, paths, lock_attempts, name) -> None:
    with ExitStack() as stack:
        paths, expected, done = CASES[name](tmp_path, paths, stack)
        assert _run(paths, name) == expected
        assert done()


def test_resume_smoke_failure_alerts_after_release_not_during(tmp_path, lock_attempts) -> None:
    paths = _setup(tmp_path)
    write_paused_state(NAME, paths)
    released: list = []
    with ExitStack() as stack, patch.object(resume_cmd, "notify") as notify:
        _resume_patches(stack, smoke=(False, "HTTP 502 on /"))
        assert _run(paths, "project.resume", released) == {}
        notify.assert_not_called()
        [after] = released
        after()
    notify.assert_called_once()
    assert "HTTP 502 on /" in notify.call_args.args[2]
    assert not is_paused(NAME, paths)


def test_resume_with_a_passing_smoke_registers_nothing(tmp_path, lock_attempts) -> None:
    paths = _setup(tmp_path)
    write_paused_state(NAME, paths)
    released: list = []
    with ExitStack() as stack:
        _resume_patches(stack)
        _run(paths, "project.resume", released)
    assert released == []


def test_resume_smoke_failure_outside_the_worker_fails_noisily(tmp_path,
                                                               lock_attempts) -> None:
    paths = _setup(tmp_path)
    write_paused_state(NAME, paths)
    action = REGISTRY.get("project.resume")
    with ExitStack() as stack, pytest.raises(RuntimeError, match="after_release"):
        _resume_patches(stack, smoke=(False, "HTTP 502 on /"))
        action.handler({"project": NAME}, _ctx(paths, None))


def test_resume_no_start_hands_to_deploy(tmp_path, lock_attempts) -> None:
    paths = _setup(tmp_path)
    write_paused_state(NAME, paths)
    mark_pause_complete(NAME, paths)
    with patch.object(operate_runtime, "resume_locked") as resume:
        assert _run(paths, "project.resume", no_start=True) == {}
    resume.assert_not_called()
    assert is_paused(NAME, paths) and awaiting_deploy(NAME, paths)


def test_resume_both_flags_is_invalid_params(paths) -> None:
    with pytest.raises(ActionError) as excinfo:
        make_invoker(paths).invoke(
            "project.resume", {"project": NAME, "no_start": True,
                               "skip_security_checks": True}, Principal.operator())
    assert excinfo.value.code is ErrorCode.INVALID_PARAMS
    assert excinfo.value.message == ("no_start starts nothing, so it takes no "
                                     "skip_security_checks")


def test_backup_result_names_the_snapshot(paths, monkeypatch) -> None:
    snap = Path("/backups") / f"{NAME}-2026-11-15T020000.tar.gz.age"
    monkeypatch.setattr(operate_runtime, "snapshot_locked",
                        lambda p, pa: backup_cmd.BackupResult(0, snapshot=snap))
    with patch.object(backup_cmd, "clear_probation_if_active") as probation:
        assert _run(paths, "project.backup") == {"snapshot": snap.name}
    probation.assert_not_called()


def test_a_backup_that_wrote_no_snapshot_fails_saying_why(paths, monkeypatch) -> None:
    monkeypatch.setattr(operate_runtime, "snapshot_locked",
                        lambda p, pa: backup_cmd.BackupResult(0, cause="its service is down"))
    with pytest.raises(RuntimeError, match="wrote no snapshot: its service is down"):
        _run(paths, "project.backup")


@pytest.mark.parametrize("name, params, args, kwargs", [
    ("project.pause", {"reason": "migrating", "no_snapshot": True},
     (NAME, "PATHS", "migrating"), {"no_snapshot": True}),
    ("project.pause", {}, (NAME, "PATHS", None), {"no_snapshot": False}),
    ("project.restore", {"snapshot": "s.tar.gz.age", "no_safety_snapshot": True},
     (NAME, "PATHS", "s.tar.gz.age"), {"safety_snapshot": False}),
    ("project.restore", {}, (NAME, "PATHS", None), {"safety_snapshot": True}),
    ("project.resume", {"skip_security_checks": True}, (NAME, "PATHS", True), {}),
    ("project.resume", {}, (NAME, "PATHS", False), {}),
])
def test_each_core_gets_the_flags(paths, monkeypatch, name, params, args, kwargs) -> None:
    calls: list = []
    rc = (0, None) if name == "project.resume" else 0
    monkeypatch.setattr(operate_runtime, CORES[name],
                        lambda *a, **k: calls.append((a, k)) or rc)
    _run(paths, name, **params)
    expected = tuple(paths if a == "PATHS" else a for a in args)
    assert calls == [(expected, kwargs)]


@pytest.mark.parametrize("name", sorted(CORES))
def test_failed_core_raises_core_failed_with_the_verb(paths, monkeypatch, name) -> None:
    failed = {"project.resume": (1, None),
              "project.backup": backup_cmd.BackupResult(1, cause="dump failed")}.get(name, 1)
    monkeypatch.setattr(operate_runtime, CORES[name], lambda *a, **k: failed)
    with pytest.raises(CoreFailed) as excinfo:
        _run(paths, name)
    assert (excinfo.value.verb, excinfo.value.rc) == (CLIS[name], 1)


@pytest.mark.parametrize("name, param, flag", [
    ("project.pause", "no_snapshot", "--no-snapshot"),
    ("project.resume", "skip_security_checks", "--skip-security-checks"),
    ("project.restore", "no_safety_snapshot", "--no-safety-snapshot"),
])
def test_flags_that_skip_a_safety_net_are_govern(paths, name, param, flag) -> None:
    with pytest.raises(ActionError) as excinfo:
        make_invoker(paths).invoke(name, {"project": NAME, param: True},
                                   Principal.agent("claude-code"))
    assert excinfo.value.code is ErrorCode.FORBIDDEN
    assert f"{param} needs the govern tier" in excinfo.value.message
    assert f"boxmunge {CLIS[name]} ... {flag}." in excinfo.value.message


def test_recover_and_abandon_are_govern_and_refused_to_agents(paths) -> None:
    for name in GOVERN:
        action = REGISTRY.get(name)
        assert (action.tier, action.agent_allowed) == (Tier.GOVERN, False)
        with pytest.raises(ActionError) as excinfo:
            make_invoker(paths).invoke(name, {"project": NAME}, Principal.agent("claude-code"))
        assert excinfo.value.code is ErrorCode.FORBIDDEN
        assert "not open to agents" in excinfo.value.message


def test_runtime_actions_are_jobs_under_the_project_lock_naming_their_command() -> None:
    assert {name: REGISTRY.get(name).cli for name in CLIS} == CLIS
    for name in CLIS:
        action = REGISTRY.get(name)
        assert (action.job, action.locks) == (True, ("project",)), name
        assert action.tier is (Tier.GOVERN if name in GOVERN else Tier.OPERATE), name
