# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from boxmunge.cve.policy import Posture
from boxmunge.cve.security_policy import policy_problem, relaxations, security_policy


def _policy(posture="balanced", dangerously=False, runtimes=None):
    return security_policy(posture=Posture(posture), dangerously=dangerously, runtimes=runtimes)


def test_the_policy_records_the_three_levers_sorted() -> None:
    assert _policy("strict", True, ["python", "node"]) == {
        "posture": "strict", "dangerously_disable_quarantine": True,
        "runtimes": ["node", "python"]}


@pytest.mark.parametrize("before,after,expected", [
    (_policy(), _policy(), []),
    (_policy(), _policy("relaxed"), ["posture balanced -> relaxed"]),
    (_policy("strict"), _policy("paranoid"), []),
    (_policy(), _policy(dangerously=True), ["dangerously_disable_quarantine turned on"]),
    (_policy(dangerously=True), _policy(), []),
    (_policy(), _policy(runtimes=["python"]),
     ["security.runtimes inferred per image -> [python]"]),
    (_policy(runtimes=["python", "node"]), _policy(runtimes=["python"]),
     ["security.runtimes [node, python] -> [python]"]),
    (_policy(runtimes=["python"]), _policy(runtimes=["node", "python"]), []),
    # Inference drops unrecognised languages: leaving a declared list is a relaxation.
    (_policy(runtimes=["python"]), _policy(),
     ["security.runtimes [python] -> inferred per image"]),
])
def test_relaxations(before, after, expected) -> None:
    assert relaxations(before, after) == expected


def test_every_relaxation_is_listed() -> None:
    assert len(relaxations(_policy("strict"), _policy("relaxed", True, ["go"]))) == 3


def test_a_malformed_policy_is_named() -> None:
    assert policy_problem(_policy()) is None
    assert policy_problem("balanced")
    assert policy_problem({**_policy(), "posture": "lax"})
    assert policy_problem({**_policy(), "dangerously_disable_quarantine": "no"})
    assert policy_problem({**_policy(), "runtimes": "python"})
