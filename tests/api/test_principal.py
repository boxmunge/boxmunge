# SPDX-License-Identifier: Apache-2.0
"""Principals and the grant table: every principal kind against every tier."""
from __future__ import annotations

import pytest

from boxmunge.api.principal import Principal, PrincipalKind, Tier, refusal

O, P, G, X = Tier.OBSERVE, Tier.OPERATE, Tier.GOVERN, Tier.PLATFORM

# (principal, agent_allowed, tiers it may use)
GRANT_MATRIX = [
    (Principal.operator("ssh"), False, {O, P, G}),
    (Principal.operator("supervisor"), False, {O, P, G}),
    (Principal.operator("upgrade-shim"), False, {O, P, G, X}),
    (Principal.agent("claude-code"), False, {O, P}),
    (Principal.agent("claude-code"), True, {O, P, G}),
    (Principal.timer("boxmunge-health", O), False, {O}),
    (Principal.timer("boxmunge-backup", P), False, {O, P}),
    (Principal.timer("boxmunge-auto-update", P), False, {O, P, X}),
    (Principal.plugin("webui", O), False, {O}),
    (Principal.plugin("webui", P), False, {O, P}),
    (Principal.plugin("webui", P), True, {O, P}),
    (Principal.assistant("assist"), False, {O}),
    (Principal.assistant("assist"), True, {O}),
    (Principal.gate(), False, set()),
    (Principal.gate(), True, set()),
]


@pytest.mark.parametrize("principal,agent_allowed,allowed", GRANT_MATRIX,
                         ids=lambda v: getattr(v, "id", repr(v)))
@pytest.mark.parametrize("tier", list(Tier), ids=lambda t: t.value)
def test_grant_matrix(principal, agent_allowed, allowed, tier) -> None:
    why = refusal(principal, tier, agent_allowed=agent_allowed)
    if tier in allowed:
        assert why is None
    else:
        assert isinstance(why, str) and why


@pytest.mark.parametrize("tier", [Tier.GOVERN, Tier.PLATFORM])
@pytest.mark.parametrize("kind", [PrincipalKind.PLUGIN, PrincipalKind.TIMER,
                                  PrincipalKind.ASSISTANT])
def test_govern_and_platform_are_never_grantable(kind, tier) -> None:
    with pytest.raises(ValueError, match="cannot be granted"):
        Principal(kind, "webui", tier)


def test_assistant_cannot_hold_operate() -> None:
    with pytest.raises(ValueError, match="assistant holds observe"):
        Principal(PrincipalKind.ASSISTANT, "assist", Tier.OPERATE)


def test_ids() -> None:
    assert Principal.operator().id == "operator:ssh"
    assert Principal.agent("claude-code").id == "agent:mcp(claude-code)"
    assert Principal.timer("boxmunge-cve-scan", Tier.OBSERVE).id == "timer:boxmunge-cve-scan"
    assert Principal.plugin("webui", Tier.OBSERVE).id == "plugin:webui"
    assert Principal.assistant("assist").id == "assistant:assist"
    assert Principal.gate().id == "gate"


@pytest.mark.parametrize("make", [
    lambda: Principal.plugin("Web UI", Tier.OBSERVE),
    lambda: Principal.plugin("webui\n", Tier.OBSERVE),
    lambda: Principal.plugin("webui", None),
    lambda: Principal.operator("telnet"),
    lambda: Principal.agent("bad client name"),
    lambda: Principal(PrincipalKind.OPERATOR, "ssh", Tier.OBSERVE),
    lambda: Principal(PrincipalKind.GATE, "x"),
])
def test_malformed_principals_are_refused(make) -> None:
    with pytest.raises(ValueError):
        make()


def test_tier_ranks_are_ordered() -> None:
    assert [t.rank for t in (O, P, G, X)] == [0, 1, 2, 3]
