# SPDX-License-Identifier: Apache-2.0
"""Registry rules: names, schemas, locks, lookup and per-principal views."""
from __future__ import annotations

import pytest

from boxmunge.api.principal import Principal, Tier
from boxmunge.api.registry import Action, Registry, RegistryError
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import BOOLEAN, RESULT_OF_ACTION, STRING, obj


def _action(name: str = "thing.get", tier: Tier = Tier.OBSERVE, **overrides) -> Action:
    fields = {
        "name": name, "tier": tier, "summary": "Read a thing.",
        "params": obj({"project": STRING}, optional=("project",)),
        "result": obj({"ok": BOOLEAN}),
        "handler": lambda params, ctx: {"ok": True},
    }
    fields.update(overrides)
    return Action(**fields)


def test_registered_actions_are_listed_by_name() -> None:
    registry = Registry()
    registry.register(_action("zeta.get"))
    registry.register(_action("alpha.get"))
    assert [a.name for a in registry.actions()] == ["alpha.get", "zeta.get"]
    assert registry.get("zeta.get").name == "zeta.get"


@pytest.mark.parametrize("overrides,message", [
    ({"name": "status"}, "<noun>.<verb>"),
    ({"name": "Status.Get"}, "<noun>.<verb>"),
    ({"name": "status.get.now"}, "<noun>.<verb>"),
    ({"summary": "  "}, "summary is empty"),
    ({"tier": "observe"}, "tier must be a Tier"),
    ({"params": {"type": "object", "properties": {}}}, "params schema: $: object schema must set"),
    ({"result": {"type": "object", "properties": {"x": STRING}}}, "result schema"),
    ({"params": STRING}, "params schema must be an object"),
    ({"locks": ("host",)}, "unknown lock(s): host"),
    ({"locks": ("project",)}, "project lock needs a required 'project' parameter"),
    ({"agent_allowed": True}, "agent_allowed applies to govern actions only"),
])
def test_definitions_that_break_a_rule_are_refused(overrides, message) -> None:
    with pytest.raises(RegistryError) as excinfo:
        Registry().register(_action(**overrides))
    assert message in str(excinfo.value)


def test_duplicate_names_are_refused() -> None:
    registry = Registry()
    registry.register(_action())
    with pytest.raises(RegistryError, match="registered twice"):
        registry.register(_action())


def test_project_lock_with_required_project_is_accepted() -> None:
    action = _action("project.touch", Tier.OPERATE, locks=("project",),
                     params=obj({"project": STRING}))
    Registry().register(action)


def test_unknown_action_is_not_found() -> None:
    with pytest.raises(ActionError) as excinfo:
        Registry().get("nope.nope")
    assert excinfo.value.code is ErrorCode.NOT_FOUND
    assert "GET /v1/actions" in excinfo.value.message


def test_available_to_applies_the_grant() -> None:
    registry = Registry()
    for tier in Tier:
        registry.register(_action(f"{tier.value}.run", tier))

    def names(principal: Principal) -> list[str]:
        return [a.name for a in registry.available_to(principal)]

    assert names(Principal.plugin("webui", Tier.OBSERVE)) == ["observe.run"]
    assert names(Principal.plugin("webui", Tier.OPERATE)) == ["observe.run", "operate.run"]
    assert names(Principal.operator()) == ["govern.run", "observe.run", "operate.run"]


def test_catalog_entry_exposes_only_the_public_fields() -> None:
    entry = _action(cli="status", mcp=True).catalog_entry()
    assert entry == {
        "name": "thing.get", "tier": "observe", "summary": "Read a thing.",
        "params": obj({"project": STRING}, optional=("project",)),
        "result": obj({"ok": BOOLEAN}), "job": False,
    }


def test_result_of_action_is_refused_outside_a_job_records_result() -> None:
    registry = Registry()
    action = Action(name="thing.get", tier=Tier.OBSERVE, summary="Test.",
                    params=obj({"result": RESULT_OF_ACTION}, optional=("result",)),
                    result=obj({}), handler=lambda params, ctx: {})
    with pytest.raises(RegistryError, match="x-result-of-action is allowed only"):
        registry.register(action)


def test_result_of_action_is_refused_in_params() -> None:
    """Callers never send job records; only results may carry the keyword."""
    registry = Registry()
    action = Action(name="thing.get", tier=Tier.OBSERVE, summary="Test.",
                    params=obj({"action": STRING, "result": RESULT_OF_ACTION},
                               optional=("action", "result")),
                    result=obj({}), handler=lambda params, ctx: {})
    with pytest.raises(RegistryError, match="params schema may not use x-result-of-action"):
        registry.register(action)


GOVERN_FLAG = {**BOOLEAN, "x-tier": "govern"}


@pytest.mark.parametrize("tier,params,cli,message", [
    (Tier.OPERATE, obj({"project": STRING, "force": GOVERN_FLAG}),
     "resume", "x-tier is allowed only on an optional property"),
    (Tier.OPERATE, obj({"limit": {"type": "integer", "x-tier": "govern"}}, optional=("limit",)),
     "resume", "x-tier is allowed only on a boolean or string property"),
    (Tier.OPERATE, obj({"note": {"type": ["string", "null"], "x-tier": "govern"}},
                       optional=("note",)),
     "resume", "x-tier is allowed only on a boolean or string property"),
    (Tier.GOVERN, obj({"force": GOVERN_FLAG}, optional=("force",)),
     "resume", "x-tier govern on force is not above the action's tier (govern)"),
    (Tier.OPERATE, obj({"force": {**BOOLEAN, "x-tier": "observe"}}, optional=("force",)),
     "resume", "x-tier observe on force is not above the action's tier (operate)"),
    (Tier.OPERATE, obj({"force": {**BOOLEAN, "x-tier": "root"}}, optional=("force",)),
     "resume", "x-tier must be one of"),
    (Tier.OPERATE, obj({"opts": obj({"force": GOVERN_FLAG}, optional=("force",))},
                       optional=("opts",)),
     "resume", "x-tier is allowed only on a top-level parameter"),
    (Tier.OPERATE, obj({"force": GOVERN_FLAG}, optional=("force",)),
     None, "an x-tier parameter needs the action's cli command"),
])
def test_registry_rejects_x_tier_on_required_or_non_boolean_string_or_not_above(
        tier, params, cli, message) -> None:
    with pytest.raises(RegistryError) as excinfo:
        Registry().register(_action("project.resume", tier, params=params, cli=cli))
    assert message in str(excinfo.value)


def test_registry_rejects_x_tier_in_a_result() -> None:
    result = obj({"ok": BOOLEAN, "forced": GOVERN_FLAG}, optional=("forced",))
    with pytest.raises(RegistryError, match="x-tier is allowed only on a top-level parameter"):
        Registry().register(_action("project.resume", Tier.OPERATE, result=result,
                                    cli="resume"))


def test_registry_accepts_a_govern_flag_on_an_operate_action() -> None:
    params = obj({"force": GOVERN_FLAG, "reason": {**STRING, "x-tier": "govern"}},
                 optional=("force", "reason"))
    Registry().register(_action("project.resume", Tier.OPERATE, params=params, cli="resume"))


def test_registry_rejects_secret_params_on_job_actions() -> None:
    params = obj({"token": {**STRING, "secret": True}}, optional=("token",))
    with pytest.raises(RegistryError, match="a job action may not have a secret parameter"):
        Registry().register(_action("project.stage", Tier.OPERATE, params=params, job=True))
    Registry().register(_action("project.stage", Tier.OPERATE, params=params))
