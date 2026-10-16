# SPDX-License-Identifier: Apache-2.0
"""Action definitions and the registry that holds them.

An Action is defined once, here or in api/actions/, with typed parameter
and result schemas, a tier, the locks it needs, and whether it runs as a
job. The CLI, the deploy shell's allowlist, the MCP tool list and the API
daemon's catalog are all derived from the registry.

A handler is a plain function (params, ctx) -> dict. It never prints and
never calls sys.exit; it raises ActionError to refuse or fail.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from boxmunge.api.context import ActionContext
from boxmunge.api.principal import Principal, Tier, refusal
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import SchemaDefinitionError, check_schema

ACTION_NAME_RE = re.compile(r"[a-z][a-z_]*\.[a-z][a-z_]*")
LOCK_NAMES = frozenset({"project"})

Handler = Callable[[dict[str, Any], ActionContext], dict[str, Any]]


@dataclass(frozen=True)
class Action:
    name: str
    tier: Tier
    summary: str
    params: dict[str, Any]
    result: dict[str, Any]
    handler: Handler
    locks: tuple[str, ...] = ()
    job: bool = False
    cli: str | None = None          # the CLI/shell command this backs
    mcp: bool = False               # expose as an MCP tool
    agent_allowed: bool = False     # a govern action an agent may run

    def catalog_entry(self) -> dict[str, Any]:
        """The public description a caller sees in GET /v1/actions."""
        return {
            "name": self.name,
            "tier": self.tier.value,
            "summary": self.summary,
            "params": self.params,
            "result": self.result,
            "job": self.job,
        }


class RegistryError(ValueError):
    """An action definition breaks a registry rule."""


class Registry:
    def __init__(self) -> None:
        self._actions: dict[str, Action] = {}

    def register(self, action: Action) -> None:
        name = action.name
        if not ACTION_NAME_RE.fullmatch(name):
            raise RegistryError(f"{name!r}: action names are <noun>.<verb>, lowercase")
        if name in self._actions:
            raise RegistryError(f"{name}: registered twice")
        if not isinstance(action.tier, Tier):
            raise RegistryError(f"{name}: tier must be a Tier")
        if not action.summary.strip():
            raise RegistryError(f"{name}: summary is empty")
        for label, schema in (("params", action.params), ("result", action.result)):
            try:
                check_schema(schema)
            except SchemaDefinitionError as e:
                raise RegistryError(f"{name}: {label} schema: {e}") from e
            if schema["type"] != "object":
                raise RegistryError(f"{name}: {label} schema must be an object")
        unknown = sorted(set(action.locks) - LOCK_NAMES)
        if unknown:
            raise RegistryError(f"{name}: unknown lock(s): {', '.join(unknown)}")
        if "project" in action.locks and "project" not in action.params.get("required", []):
            raise RegistryError(f"{name}: the project lock needs a required 'project' parameter")
        if action.agent_allowed and action.tier is not Tier.GOVERN:
            raise RegistryError(f"{name}: agent_allowed applies to govern actions only")
        self._actions[name] = action

    def get(self, name: str) -> Action:
        action = self._actions.get(name)
        if action is None:
            raise ActionError(
                ErrorCode.NOT_FOUND,
                f"Unknown action {name[:80]!r}. GET /v1/actions lists the actions "
                f"available to you.",
            )
        return action

    def actions(self) -> tuple[Action, ...]:
        return tuple(self._actions[name] for name in sorted(self._actions))

    def available_to(self, principal: Principal) -> tuple[Action, ...]:
        return tuple(
            a for a in self.actions()
            if refusal(principal, a.tier, agent_allowed=a.agent_allowed) is None
        )
