# SPDX-License-Identifier: Apache-2.0
"""invoke(): admission, auditing, locks and result checking."""
from __future__ import annotations

import pytest

from boxmunge.api.audit import AuditError, AuditLog
from boxmunge.api.invoke import Invoker
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.registry import Action, Registry
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import BOOLEAN, obj
from boxmunge.fileutil import project_lock
from boxmunge.state import StateError
from tests.api.fakes import StubHost, make_invoker, read_audit

PROJECT = {"type": "string", "pattern": "[a-z0-9][a-z0-9-]{0,62}"}
OPERATOR = Principal.operator()
WEBUI = Principal.plugin("webui", Tier.OBSERVE)
WEBUI_OPERATE = Principal.plugin("webui", Tier.OPERATE)


class Calls:
    def __init__(self) -> None:
        self.seen: list[tuple[dict, object]] = []

    def handler(self, result=None, raises: BaseException | None = None):
        def run(params, ctx):
            self.seen.append((params, ctx))
            if raises is not None:
                raise raises
            return {"ok": True} if result is None else result
        return run


def _registry(*actions: Action) -> Registry:
    registry = Registry()
    for action in actions:
        registry.register(action)
    return registry


def _action(name: str, tier: Tier = Tier.OBSERVE, handler=None, **overrides) -> Action:
    fields = {
        "name": name, "tier": tier, "summary": "Test action.",
        "params": obj({"project": PROJECT, "token": {"type": "string", "secret": True}},
                      optional=("project", "token")),
        "result": obj({"ok": BOOLEAN}),
        "handler": handler or (lambda params, ctx: {"ok": True}),
    }
    fields.update(overrides)
    return Action(**fields)


def _refused(paths, code: ErrorCode) -> dict:
    record = read_audit(paths)[-1]
    assert record["outcome"] == "refused" and record["code"] == code.value
    assert record["params"] is None
    return record


def test_observe_call_returns_data_and_is_not_audited(paths) -> None:
    calls = Calls()
    invoker = make_invoker(paths, registry=_registry(_action("thing.get", handler=calls.handler())))
    result = invoker.invoke("thing.get", {"project": "shop"}, WEBUI)
    assert (result.action, result.data) == ("thing.get", {"ok": True})
    params, ctx = calls.seen[0]
    assert params == {"project": "shop"}
    assert ctx.principal == WEBUI and ctx.paths is paths and ctx.emit is None
    assert read_audit(paths) == []


def test_unknown_action_is_refused_and_audited(paths) -> None:
    invoker = make_invoker(paths, registry=_registry())
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("nope.nope", {}, WEBUI)
    assert excinfo.value.code is ErrorCode.NOT_FOUND
    record = _refused(paths, ErrorCode.NOT_FOUND)
    assert (record["principal"], record["action"]) == ("plugin:webui", "nope.nope")


def test_an_oversized_unknown_name_is_audited_truncated(paths) -> None:
    """A client-chosen name is written to the audit log; one request must
    not be able to append tens of kilobytes to an append-only file."""
    invoker = make_invoker(paths, registry=_registry())
    with pytest.raises(ActionError):
        invoker.invoke("x" * 60000, {}, WEBUI)
    record = _refused(paths, ErrorCode.NOT_FOUND)
    assert record["action"] == "x" * 128 + "...(59872 more characters)"
    assert len(paths.audit_log.read_bytes()) < 1024


def test_grant_refusal_runs_nothing(paths) -> None:
    calls = Calls()
    invoker = make_invoker(paths, registry=_registry(
        _action("project.poke", Tier.OPERATE, handler=calls.handler())))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("project.poke", {}, WEBUI)
    assert excinfo.value.code is ErrorCode.FORBIDDEN
    assert calls.seen == []
    _refused(paths, ErrorCode.FORBIDDEN)


def test_served_tiers_refuse_even_the_operator(paths) -> None:
    calls = Calls()
    invoker = make_invoker(paths, served_tiers=frozenset({Tier.OBSERVE}), registry=_registry(
        _action("project.poke", Tier.OPERATE, handler=calls.handler())))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("project.poke", {}, OPERATOR)
    assert excinfo.value.code is ErrorCode.FORBIDDEN
    assert "does not serve operate actions" in excinfo.value.message
    assert calls.seen == []


@pytest.mark.parametrize("params,violation", [
    ({"project": "shop\n"}, "$.project: does not match pattern"),
    ({"project": 7}, "$.project: expected string, got integer"),
    ({"extra": True}, "$: unexpected property 'extra'"),
])
def test_invalid_params_list_every_violation(paths, params, violation) -> None:
    invoker = make_invoker(paths, registry=_registry(_action("thing.get")))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("thing.get", params, WEBUI)
    assert excinfo.value.code is ErrorCode.INVALID_PARAMS
    assert any(v.startswith(violation) for v in excinfo.value.details["violations"])
    _refused(paths, ErrorCode.INVALID_PARAMS)


def test_params_must_be_an_object(paths) -> None:
    invoker = make_invoker(paths, registry=_registry(_action("thing.get")))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("thing.get", ["shop"], WEBUI)
    assert excinfo.value.code is ErrorCode.INVALID_PARAMS


@pytest.mark.parametrize("approval,code", [
    (None, ErrorCode.APPROVAL_REQUIRED),
    ({"approval_id": "01J"}, ErrorCode.APPROVAL_INVALID),
])
def test_plugin_operate_calls_need_an_approval(paths, approval, code) -> None:
    calls = Calls()
    invoker = make_invoker(paths, registry=_registry(
        _action("project.poke", Tier.OPERATE, handler=calls.handler())))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("project.poke", {}, WEBUI_OPERATE, approval)
    assert excinfo.value.code is code
    assert calls.seen == []
    _refused(paths, code)


def test_approval_on_any_other_call_is_invalid(paths) -> None:
    invoker = make_invoker(paths, registry=_registry(_action("thing.get")))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("thing.get", {}, OPERATOR, {"approval_id": "01J"})
    assert excinfo.value.code is ErrorCode.INVALID_PARAMS


def test_non_observe_call_is_audited_with_secrets_redacted(paths) -> None:
    invoker = make_invoker(paths, registry=_registry(_action("secret.set", Tier.GOVERN)))
    invoker.invoke("secret.set", {"project": "shop", "token": "hunter2"}, OPERATOR)
    accepted, outcome = read_audit(paths)
    assert accepted["outcome"] == "accepted" and outcome["outcome"] == "succeeded"
    assert accepted["params"] == {"project": "shop", "token": "<redacted>"}
    assert "hunter2" not in paths.audit_log.read_text()


def test_unwritable_audit_log_refuses_and_runs_nothing(paths) -> None:
    calls = Calls()
    invoker = Invoker(_registry(_action("secret.set", Tier.GOVERN, handler=calls.handler())),
                      paths, StubHost(), AuditLog(paths.root / "no-such-dir" / "audit.jsonl"))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("secret.set", {}, OPERATOR)
    assert excinfo.value.code is ErrorCode.UNAVAILABLE
    assert "did not run" in excinfo.value.message
    assert calls.seen == []


def test_job_actions_need_a_job_runner(paths) -> None:
    invoker = make_invoker(paths, registry=_registry(_action("project.stage", Tier.OPERATE,
                                                             job=True)))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("project.stage", {}, OPERATOR)
    assert excinfo.value.code is ErrorCode.UNAVAILABLE
    _refused(paths, ErrorCode.UNAVAILABLE)


def test_held_project_lock_is_busy(paths) -> None:
    calls = Calls()
    action = _action("project.poke", Tier.OPERATE, handler=calls.handler(),
                     locks=("project",), params=obj({"project": PROJECT}))
    invoker = make_invoker(paths, registry=_registry(action))
    with project_lock("shop", paths):
        with pytest.raises(ActionError) as excinfo:
            invoker.invoke("project.poke", {"project": "shop"}, OPERATOR)
    assert excinfo.value.code is ErrorCode.BUSY
    assert excinfo.value.details == {"lock": "project", "project": "shop"}
    assert calls.seen == []
    assert [r["outcome"] for r in read_audit(paths)] == ["accepted", "failed"]


def test_lock_is_held_while_the_handler_runs(paths) -> None:
    def handler(params, ctx):
        from boxmunge.fileutil import LockError
        with pytest.raises(LockError):
            with project_lock("shop", paths):
                pass
        return {"ok": True}
    action = _action("project.poke", Tier.OPERATE, handler=handler,
                     locks=("project",), params=obj({"project": PROJECT}))
    make_invoker(paths, registry=_registry(action)).invoke(
        "project.poke", {"project": "shop"}, OPERATOR)


def test_unreadable_state_fails_with_the_reason(paths) -> None:
    error = StateError("Cannot read state file /x/health.json: Expecting value")
    invoker = make_invoker(paths, registry=_registry(
        _action("thing.get", handler=Calls().handler(raises=error))))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("thing.get", {}, WEBUI)
    assert excinfo.value.code is ErrorCode.FAILED
    assert excinfo.value.message == str(error)


def test_handler_action_errors_pass_through(paths) -> None:
    error = ActionError(ErrorCode.CONFLICT, "Project is paused.")
    invoker = make_invoker(paths, registry=_registry(
        _action("thing.get", handler=Calls().handler(raises=error))))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("thing.get", {}, WEBUI)
    assert excinfo.value is error


def test_result_outside_its_schema_is_a_failure(paths) -> None:
    invoker = make_invoker(paths, registry=_registry(
        _action("thing.get", handler=Calls().handler(result={"ok": "yes"}))))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("thing.get", {}, WEBUI)
    assert excinfo.value.code is ErrorCode.FAILED
    assert excinfo.value.details == {"violations": ["$.ok: expected boolean, got string"]}


def test_bugs_propagate_after_the_outcome_is_recorded(paths) -> None:
    invoker = make_invoker(paths, registry=_registry(_action(
        "project.poke", Tier.OPERATE, handler=Calls().handler(raises=RuntimeError("boom")))))
    with pytest.raises(RuntimeError, match="boom"):
        invoker.invoke("project.poke", {}, OPERATOR)
    outcome = read_audit(paths)[-1]
    assert outcome["outcome"] == "failed"
    assert outcome["message"] == "internal error: RuntimeError: boom"


def test_lost_outcome_record_is_logged_and_alerted(paths, monkeypatch) -> None:
    class FailsAfterFirst(AuditLog):
        writes = 0

        def append(self, record):
            FailsAfterFirst.writes += 1
            if FailsAfterFirst.writes > 1:
                raise AuditError("disk full")
            super().append(record)

    alerts: list[tuple[str, str]] = []
    monkeypatch.setattr("boxmunge.api.invoke.notify",
                        lambda paths, title, body, **kw: alerts.append((title, body)))
    invoker = Invoker(_registry(_action("secret.set", Tier.GOVERN)), paths, StubHost(),
                      FailsAfterFirst(paths.audit_log))
    assert invoker.invoke("secret.set", {}, OPERATOR).data == {"ok": True}
    assert alerts and "disk full" in alerts[0][1]
    assert "could not record the outcome" in paths.log_file.read_text()


def test_catalog_follows_grant_and_served_tiers(paths) -> None:
    registry = _registry(*(_action(f"{t.value}.run", t) for t in Tier))
    everything = make_invoker(paths, registry=registry)
    assert [e["name"] for e in everything.catalog(WEBUI_OPERATE)] == ["observe.run", "operate.run"]
    observe_only = make_invoker(paths, registry=registry, served_tiers=frozenset({Tier.OBSERVE}))
    assert [e["name"] for e in observe_only.catalog(OPERATOR)] == ["observe.run"]
