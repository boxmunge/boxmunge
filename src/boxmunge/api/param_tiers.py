# SPDX-License-Identifier: Apache-2.0
"""Parameters that raise the tier of the call that uses them.

An everyday action keeps its own tier, but a flag that weakens a control
(accepting a stale KEV listing, resuming without the security checks)
needs a higher one. The parameter's schema says so with the annotation
`"x-tier": "govern"`. A boolean counts when it is true; a string counts
when it is present. invoke() checks the principal's grant against the
call's effective tier, so an agent can resume a project but cannot skip
its checks.

The registry calls tier_rule_problem() so that a definition breaking these
rules never loads: the annotation sits only on a top-level parameter,
names a tier above the action's own, and the action names the CLI command
the operator runs instead.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from boxmunge.api.principal import Principal, Tier, refusal
from boxmunge.api.schema import X_TIER, keyword_values

if TYPE_CHECKING:
    from boxmunge.api.registry import Action


def param_tiers(params_schema: dict[str, Any]) -> dict[str, Tier]:
    """Each top-level parameter that carries x-tier, with the tier it names."""
    return {name: Tier(sub[X_TIER])
            for name, sub in params_schema["properties"].items() if X_TIER in sub}


def tier_rule_problem(action: Action) -> str | None:
    """Why *action*'s x-tier annotations break a registry rule, or None."""
    tiers = param_tiers(action.params)
    nested = len(keyword_values(action.params, X_TIER)) != len(tiers)
    if nested or keyword_values(action.result, X_TIER):
        return f"{X_TIER} is allowed only on a top-level parameter"
    for name, tier in tiers.items():
        if tier.rank <= action.tier.rank:
            return (f"{X_TIER} {tier.value} on {name} is not above the action's tier "
                    f"({action.tier.value})")
    if tiers and action.cli is None:
        return (f"an {X_TIER} parameter needs the action's cli command, which its "
                f"refusal names")
    return None


def effective_tier(action: Action, params: dict[str, Any]) -> tuple[Tier, list[str]]:
    """The highest tier this call needs, and the parameters that raised it.

    *params* has passed the action's schema, so an x-tier boolean present
    is a bool.
    """
    used = {name: tier for name, tier in param_tiers(action.params).items()
            if name in params and params[name] is not False}
    tier = max([action.tier, *used.values()], key=lambda t: t.rank)
    return tier, [name for name, param_tier in used.items() if param_tier is tier]


def param_tier_refusal(action: Action, params: dict[str, Any], principal: Principal,
                       served: frozenset[Tier]) -> str | None:
    """Why *principal* may not make this call at the tier its parameters raise
    it to, or None. The action's own tier has already been admitted."""
    tier, raised = effective_tier(action, params)
    if tier is action.tier:
        return None
    why = refusal(principal, tier, agent_allowed=False)
    if why is None and tier not in served:
        why = f"This server does not serve {tier.value} actions."
    if why is None:
        return None
    flag = raised[0].replace("_", "-")
    return (f"{raised[0]} needs the {tier.value} tier: {why.rstrip('.')}. The operator "
            f"runs it over SSH: boxmunge {action.cli} ... --{flag}.")
