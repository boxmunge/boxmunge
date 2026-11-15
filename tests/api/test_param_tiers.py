# SPDX-License-Identifier: Apache-2.0
"""Parameters that weaken a control raise the call's tier (x-tier)."""
from __future__ import annotations

import pytest

from boxmunge.api.param_tiers import effective_tier
from boxmunge.api.principal import GRANTABLE, Principal, Tier
from boxmunge.api.registry import Action, Registry
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import BOOLEAN, STRING, obj
from tests.api.fakes import make_invoker, read_audit

PROJECT = {"type": "string", "pattern": "[a-z0-9][a-z0-9-]{0,62}"}
GOVERN_FLAG = {**BOOLEAN, "x-tier": "govern"}
GOVERN_TEXT = {**STRING, "x-tier": "govern"}


def _resume(handler=None) -> Action:
    return Action(
        name="project.resume", tier=Tier.OPERATE, summary="Resume a project.",
        params=obj({"project": PROJECT, "skip_checks": GOVERN_FLAG,
                    "accept_stale": GOVERN_TEXT, "quiet": BOOLEAN},
                   optional=("skip_checks", "accept_stale", "quiet")),
        result=obj({"ok": BOOLEAN}),
        handler=handler or (lambda params, ctx: {"ok": True}),
        cli="resume",
    )


def _invoker(paths, seen: list | None = None):
    registry = Registry()
    registry.register(_resume(
        None if seen is None else (lambda p, ctx: seen.append(p) or {"ok": True})))
    return make_invoker(paths, registry=registry)


def test_true_govern_flag_raises_the_tier() -> None:
    assert effective_tier(_resume(), {"project": "shop", "skip_checks": True}) == (
        Tier.GOVERN, ["skip_checks"])


@pytest.mark.parametrize("params", [
    {"project": "shop"},
    {"project": "shop", "skip_checks": False},
    {"project": "shop", "skip_checks": False, "quiet": True},
])
def test_false_or_absent_flag_keeps_operate(params) -> None:
    assert effective_tier(_resume(), params) == (Tier.OPERATE, [])


def test_present_govern_string_raises_the_tier() -> None:
    params = {"project": "shop", "accept_stale": "", "skip_checks": True}
    assert effective_tier(_resume(), params) == (Tier.GOVERN, ["skip_checks", "accept_stale"])


def test_agent_is_refused_a_govern_flag_and_told_the_ssh_command(paths) -> None:
    seen: list = []
    invoker = _invoker(paths, seen)
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("project.resume", {"project": "shop", "skip_checks": True},
                       Principal.agent("claude-code"))
    error = excinfo.value
    assert error.code is ErrorCode.FORBIDDEN
    assert error.message == (
        "skip_checks needs the govern tier: This govern action is not open to agents; "
        "the operator runs it over SSH. The operator runs it over SSH: "
        "boxmunge resume ... --skip-checks.")
    assert seen == []
    record = read_audit(paths)[-1]
    assert (record["outcome"], record["code"]) == ("refused", "forbidden")


def test_agent_may_use_the_action_without_the_flag(paths) -> None:
    seen: list = []
    _invoker(paths, seen).invoke("project.resume", {"project": "shop", "skip_checks": False},
                                 Principal.agent("claude-code"))
    assert seen == [{"project": "shop", "skip_checks": False}]


@pytest.mark.parametrize("grant", sorted(GRANTABLE, key=lambda t: t.rank),
                         ids=lambda t: t.value)
def test_plugin_is_refused_a_govern_flag_whatever_its_grant(paths, grant) -> None:
    seen: list = []
    invoker = _invoker(paths, seen)
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("project.resume", {"project": "shop", "accept_stale": "kev"},
                       Principal.plugin("webui", grant))
    assert excinfo.value.code is ErrorCode.FORBIDDEN
    if grant is Tier.OPERATE:
        assert excinfo.value.message.startswith("accept_stale needs the govern tier: ")
        assert excinfo.value.message.endswith("boxmunge resume ... --accept-stale.")
    assert seen == []


def test_operator_may_use_a_govern_flag(paths) -> None:
    seen: list = []
    params = {"project": "shop", "skip_checks": True, "accept_stale": "kev"}
    _invoker(paths, seen).invoke("project.resume", params, Principal.operator())
    assert seen == [params]


def test_a_server_that_does_not_serve_govern_refuses_the_flag(paths) -> None:
    registry = Registry()
    registry.register(_resume())
    invoker = make_invoker(paths, registry=registry,
                           served_tiers=frozenset({Tier.OBSERVE, Tier.OPERATE}))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("project.resume", {"project": "shop", "skip_checks": True},
                       Principal.operator())
    assert excinfo.value.code is ErrorCode.FORBIDDEN
    assert "skip_checks needs the govern tier" in excinfo.value.message
    assert "does not serve govern" in excinfo.value.message
