# SPDX-License-Identifier: Apache-2.0
"""Who is calling, and which tiers of action they may use.

A Principal is fixed by how the caller reached boxmunge (SSH login, MCP
session, systemd unit, a plugin's socket), never by anything the caller
sends. refusal() is the grant table of the design: it says why a principal
may not use an action of a tier, or None when it may. Approvals for plugin
operate calls are checked separately, in invoke().
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class Tier(Enum):
    OBSERVE = "observe"
    OPERATE = "operate"
    GOVERN = "govern"
    PLATFORM = "platform"

    @property
    def rank(self) -> int:
        return _TIER_ORDER.index(self)


_TIER_ORDER = (Tier.OBSERVE, Tier.OPERATE, Tier.GOVERN, Tier.PLATFORM)


class PrincipalKind(Enum):
    OPERATOR = "operator"
    AGENT = "agent"
    TIMER = "timer"
    PLUGIN = "plugin"
    ASSISTANT = "assistant"
    GATE = "gate"


# The only tiers a grant can hold. govern and platform are never grantable.
GRANTABLE = frozenset({Tier.OBSERVE, Tier.OPERATE})
OPERATOR_VIAS = frozenset({"ssh", "supervisor", "upgrade-shim"})
AUTO_UPDATE_TIMER = "boxmunge-auto-update"
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_CLIENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_GRANTED_KINDS = frozenset({PrincipalKind.TIMER, PrincipalKind.PLUGIN,
                            PrincipalKind.ASSISTANT})


@dataclass(frozen=True)
class Principal:
    """A caller. *name* is the SSH route for an operator, the self-reported
    client for an agent, the unit for a timer, the plugin name otherwise."""

    kind: PrincipalKind
    name: str = ""
    grant: Tier | None = None

    def __post_init__(self) -> None:
        kind = self.kind
        if kind is PrincipalKind.GATE:
            if self.name or self.grant is not None:
                raise ValueError("the gate principal takes no name and no grant")
            return
        if kind is PrincipalKind.OPERATOR:
            if self.name not in OPERATOR_VIAS:
                raise ValueError(f"operator route must be one of {sorted(OPERATOR_VIAS)}, "
                                 f"not {self.name!r}")
        elif kind is PrincipalKind.AGENT:
            if not _CLIENT_RE.fullmatch(self.name):
                raise ValueError(f"invalid agent client name {self.name!r}")
        elif not _NAME_RE.fullmatch(self.name):
            raise ValueError(f"invalid {kind.value} name {self.name!r}")
        needs_grant = kind in _GRANTED_KINDS
        if needs_grant and self.grant is None:
            raise ValueError(f"a {kind.value} principal needs a grant")
        if not needs_grant and self.grant is not None:
            raise ValueError(f"a {kind.value} principal takes no grant")
        if needs_grant and self.grant not in GRANTABLE:
            raise ValueError(f"{self.grant.value} cannot be granted to a {kind.value}; "
                             f"grants are observe or operate")
        if kind is PrincipalKind.ASSISTANT and self.grant is not Tier.OBSERVE:
            raise ValueError("an assistant holds observe; its operate output is a proposal")

    @property
    def id(self) -> str:
        if self.kind is PrincipalKind.GATE:
            return "gate"
        if self.kind is PrincipalKind.AGENT:
            return f"agent:mcp({self.name})"
        return f"{self.kind.value}:{self.name}"

    @classmethod
    def operator(cls, via: str = "ssh") -> Principal:
        return cls(PrincipalKind.OPERATOR, via)

    @classmethod
    def agent(cls, client: str) -> Principal:
        return cls(PrincipalKind.AGENT, client)

    @classmethod
    def timer(cls, unit: str, grant: Tier) -> Principal:
        return cls(PrincipalKind.TIMER, unit, grant)

    @classmethod
    def plugin(cls, name: str, grant: Tier) -> Principal:
        return cls(PrincipalKind.PLUGIN, name, grant)

    @classmethod
    def assistant(cls, name: str) -> Principal:
        return cls(PrincipalKind.ASSISTANT, name, Tier.OBSERVE)

    @classmethod
    def gate(cls) -> Principal:
        return cls(PrincipalKind.GATE)


def refusal(principal: Principal, tier: Tier, *, agent_allowed: bool = False) -> str | None:
    """Why *principal* may not use an action of *tier*, or None if it may."""
    kind = principal.kind
    if kind is PrincipalKind.GATE:
        return "The gate may only read and complete pending approvals."
    if kind is PrincipalKind.OPERATOR:
        if tier is Tier.PLATFORM and principal.name != "upgrade-shim":
            return "Platform actions run only through the root upgrade shim."
        return None
    if kind is PrincipalKind.AGENT:
        if tier is Tier.PLATFORM:
            return "Agents may not run platform actions."
        if tier is Tier.GOVERN and not agent_allowed:
            return "This govern action is not open to agents; the operator runs it over SSH."
        return None
    if kind is PrincipalKind.TIMER:
        if tier is Tier.GOVERN:
            return "Timers may not run govern actions."
        if tier is Tier.PLATFORM:
            if principal.name == AUTO_UPDATE_TIMER:
                return None
            return f"Only {AUTO_UPDATE_TIMER} may run platform actions."
        return _within_grant(principal, tier)
    if tier in (Tier.GOVERN, Tier.PLATFORM):
        return f"{tier.value} actions are never available to {kind.value}s."
    if kind is PrincipalKind.ASSISTANT and tier is Tier.OPERATE:
        return "Assistants propose operate actions; the operator applies the proposal."
    return _within_grant(principal, tier)


def _within_grant(principal: Principal, tier: Tier) -> str | None:
    assert principal.grant is not None
    if tier.rank <= principal.grant.rank:
        return None
    return f"{principal.id} is granted {principal.grant.value} only."
