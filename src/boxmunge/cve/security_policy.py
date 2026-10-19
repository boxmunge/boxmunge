# SPDX-License-Identifier: Apache-2.0
"""The security policy a project is judged under, as a quarantine records it.

A release that ships a fix for a quarantined project is scanned under its own
manifest's policy, so it may also lift the quarantine by relaxing that policy.
The quarantine record keeps the policy in force when the project was
quarantined; `relaxations` names what a release loosened against it.
"""
from __future__ import annotations

from typing import Any

from boxmunge.cve.policy_types import Posture


def security_policy(*, posture: Posture, dangerously: bool,
                    runtimes: list[str] | None) -> dict[str, Any]:
    """The three manifest levers that decide what a finding does."""
    return {"posture": posture.value, "dangerously_disable_quarantine": dangerously,
            "runtimes": sorted(runtimes) if runtimes is not None else None}


def policy_problem(policy: Any) -> str | None:
    """Why *policy* is not what `security_policy` returns, or None."""
    if not isinstance(policy, dict):
        return "is not a mapping"
    runtimes = policy.get("runtimes")
    if policy.get("posture") not in {p.value for p in Posture}:
        return "has an unknown posture"
    if not isinstance(policy.get("dangerously_disable_quarantine"), bool):
        return "has a dangerously_disable_quarantine that is not true or false"
    if runtimes is not None and not (isinstance(runtimes, list)
                                     and all(isinstance(r, str) for r in runtimes)):
        return "has runtimes that are neither null nor a list of names"
    return None


def _runtimes(value: list[str] | None) -> str:
    return "inferred per image" if value is None else "[" + ", ".join(value) + "]"


def relaxations(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """What *after* loosens against *before*, in words. A tighter posture is
    not listed. A runtime list counts when it may exempt packages the old
    judgement covered: declared where it was inferred, or missing a runtime
    the old list had."""
    found: list[str] = []
    order = [p.value for p in Posture]
    if order.index(after["posture"]) < order.index(before["posture"]):
        found.append(f"posture {before['posture']} -> {after['posture']}")
    if after["dangerously_disable_quarantine"] and not before["dangerously_disable_quarantine"]:
        found.append("dangerously_disable_quarantine turned on")
    old, new = before["runtimes"], after["runtimes"]
    if new is not None and (old is None or not set(old) <= set(new)):
        found.append(f"security.runtimes {_runtimes(old)} -> {_runtimes(new)}")
    return found
