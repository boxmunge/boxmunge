# SPDX-License-Identifier: Apache-2.0
"""Release operate actions: project.stage, promote, unstage, deploy, rollback.

Each is a job over a lock-free *_locked core: the job worker holds the
project lock, so a handler that reaches for it fails these tests.
"""
from __future__ import annotations

import pytest

from boxmunge.api.actions import build_registry, operate_release
from boxmunge.api.context import ActionContext
from boxmunge.api.job_capture import CoreFailed
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import validate
from boxmunge.commands import kev_acceptance
from boxmunge.commands import security_regression_guard as guard
from boxmunge.project_registry import add_project
from boxmunge.staged_release import load_slot
from tests.api.fakes import StubHost, make_invoker, registry_results
from tests.bundle_helpers import place_bundle
from tests.stage_helpers import V1, V2, V3, staging_docker_off

NAME = "myapp"
REGISTRY = build_registry()
CORES = {
    "project.stage": "stage_locked", "project.promote": "promote_locked",
    "project.unstage": "unstage_locked", "project.deploy": "deploy_locked",
    "project.rollback": "rollback_locked",
}
GUARDED = ("project.stage", "project.promote", "project.deploy", "project.rollback")


def _ctx(paths) -> ActionContext:
    return ActionContext(principal=Principal.operator(), paths=paths, host=StubHost(),
                         result_schemas=registry_results)


def _run(paths, name: str, **params) -> dict:
    action = REGISTRY.get(name)
    params = {"project": NAME, **params}
    assert validate(action.params, params) == []
    data = action.handler(params, _ctx(paths))
    assert validate(action.result, data, result_schemas=registry_results) == []
    return data


def _version(paths) -> str:
    return (paths.project_dir(NAME) / "VERSION").read_text()


def test_each_release_handler_runs_its_core_with_the_lock_patched_to_raise(
        paths, lock_attempts) -> None:
    add_project(NAME, paths)

    def upload(ts: str, version: str) -> None:  # a release takes its bundle from the inbox
        place_bundle(paths, timestamp=ts, files={"VERSION": version})

    with staging_docker_off():
        upload(V1, "v1\n")
        assert _run(paths, "project.deploy", ref=V1) == {}
        assert _version(paths) == "v1\n"
        upload(V2, "v2\n")
        _run(paths, "project.stage", ref=V2)
        assert _run(paths, "project.unstage") == {}
        assert load_slot(paths, NAME) is None
        upload(V2, "v2\n")
        _run(paths, "project.stage", ref=V2)
        assert _run(paths, "project.promote") == {}
        assert _version(paths) == "v2\n" and load_slot(paths, NAME) is None
        upload(V3, "v3\n")
        _run(paths, "project.deploy", ref=V3)
        assert _version(paths) == "v3\n"
        assert _run(paths, "project.rollback") == {}
    assert _version(paths) == "v2\n"


def test_stage_result_is_the_slot_ref_and_id(paths, lock_attempts) -> None:
    add_project(NAME, paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with staging_docker_off():
        _run(paths, "project.deploy", ref=V1)
        data = _run(paths, "project.stage", ref=V2)
    slot = load_slot(paths, NAME)
    assert data == {"ref": slot.ref, "id": slot.id}
    assert slot.ref == f"{NAME}-{V2}"


def _recording_core(calls: list, rc: int = 0):
    def core(*args, **kwargs):
        override = guard._CURRENT.get()
        acceptance = kev_acceptance._CURRENT.get()
        calls.append({
            "args": args, "kwargs": kwargs,
            "reason": override.reason if override else "no override context",
            "accepted": acceptance.accepted if acceptance else None,
        })
        return rc
    return core


def test_deploy_passes_every_flag_to_the_core(paths, monkeypatch) -> None:
    calls: list = []
    monkeypatch.setattr(operate_release, "deploy_locked", _recording_core(calls))
    _run(paths, "project.deploy", ref=V2, no_snapshot=True, no_pull=True, redeploy=True,
         accept_stale_kev=True, allow_security_regression="hotfix")
    [call] = calls
    assert call["args"] == (NAME, paths)
    assert call["kwargs"] == {"ref": V2, "no_snapshot": True, "dry_run": False,
                              "pull": False, "redeploy": True}
    assert (call["reason"], call["accepted"]) == ("hotfix", True)


def test_deploy_defaults_match_the_cli(paths, monkeypatch) -> None:
    calls: list = []
    monkeypatch.setattr(operate_release, "deploy_locked", _recording_core(calls))
    _run(paths, "project.deploy")
    [call] = calls
    assert call["kwargs"] == {"ref": None, "no_snapshot": False, "dry_run": False,
                              "pull": True, "redeploy": False}
    assert (call["reason"], call["accepted"]) == (None, False)


@pytest.mark.parametrize("name, params, kwargs", [
    ("project.stage", {"ref": V2, "no_pull": True},
     {"ref": V2, "dry_run": False, "pull": False}),
    ("project.promote", {"no_pull": True}, {"dry_run": False, "pull": False}),
    ("project.unstage", {}, {"dry_run": False}),
    ("project.rollback", {}, {}),
])
def test_each_core_gets_the_flags_and_no_dry_run(paths, monkeypatch, name, params,
                                                 kwargs) -> None:
    calls: list = []
    monkeypatch.setattr(operate_release, CORES[name], _recording_core(calls))
    monkeypatch.setattr(operate_release, "load_slot", lambda p, n: _Slot())
    _run(paths, name, **params)
    [call] = calls
    assert (call["args"], call["kwargs"]) == ((NAME, paths), kwargs)


class _Slot:
    ref, id = V2, "01JSTAGED"


@pytest.mark.parametrize("name", GUARDED)
def test_regression_reason_reaches_the_guard(paths, monkeypatch, name) -> None:
    calls: list = []
    monkeypatch.setattr(operate_release, CORES[name], _recording_core(calls))
    monkeypatch.setattr(operate_release, "load_slot", lambda p, n: _Slot())
    _run(paths, name, allow_security_regression="  vendor fix is out Monday ")
    _run(paths, name)
    assert [c["reason"] for c in calls] == ["vendor fix is out Monday", None]


def test_a_blank_regression_reason_is_refused_before_anything_runs(paths) -> None:
    with pytest.raises(ActionError) as excinfo:
        make_invoker(paths).invoke("project.stage",
                                   {"project": NAME, "allow_security_regression": "   "},
                                   Principal.operator())
    assert excinfo.value.code is ErrorCode.INVALID_PARAMS
    assert "allow_security_regression" in excinfo.value.message
    assert "logged and alerted" in excinfo.value.message


@pytest.mark.parametrize("name, param, value, flag, cli", [
    ("project.deploy", "accept_stale_kev", True, "--accept-stale-kev", "prod-deploy"),
    ("project.deploy", "no_snapshot", True, "--no-snapshot", "prod-deploy"),
    *[(name, "allow_security_regression", "why", "--allow-security-regression",
       REGISTRY.get(name).cli) for name in GUARDED],
])
def test_accept_stale_kev_is_govern(paths, name, param, value, flag, cli) -> None:
    """Decision 2: a flag that weakens a control needs govern, so an agent
    can deploy but not past the KEV or regression check, nor without the
    snapshot a rollback restores."""
    with pytest.raises(ActionError) as excinfo:
        make_invoker(paths).invoke(name, {"project": NAME, param: value},
                                   Principal.agent("claude-code"))
    assert excinfo.value.code is ErrorCode.FORBIDDEN
    assert f"{param} needs the govern tier" in excinfo.value.message
    assert f"boxmunge {cli} ... {flag}." in excinfo.value.message


def test_everyday_flags_stay_operate(paths) -> None:
    """Without the control-weakening flags an agent gets as far as the job
    check (this build has no runner): its tier admitted the call."""
    with pytest.raises(ActionError) as excinfo:
        make_invoker(paths).invoke(
            "project.deploy", {"project": NAME, "no_pull": True, "redeploy": True,
                               "no_snapshot": False, "accept_stale_kev": False},
            Principal.agent("claude-code"))
    assert excinfo.value.code is ErrorCode.UNAVAILABLE
    assert "runs as a job" in excinfo.value.message


@pytest.mark.parametrize("name", sorted(CORES))
def test_failed_core_raises_core_failed_with_the_verb(paths, monkeypatch, name) -> None:
    monkeypatch.setattr(operate_release, CORES[name], _recording_core([], rc=1))
    with pytest.raises(CoreFailed) as excinfo:
        _run(paths, name)
    assert (excinfo.value.verb, excinfo.value.rc) == (REGISTRY.get(name).cli, 1)


def test_release_actions_are_operate_jobs_naming_their_command() -> None:
    assert {name: REGISTRY.get(name).cli for name in CORES} == {
        "project.stage": "stage", "project.promote": "promote",
        "project.unstage": "unstage", "project.deploy": "prod-deploy",
        "project.rollback": "rollback",
    }
    for name in CORES:
        action = REGISTRY.get(name)
        assert (action.tier, action.job, action.locks) == (Tier.OPERATE, True, ("project",))
