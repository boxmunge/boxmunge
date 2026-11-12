# SPDX-License-Identifier: Apache-2.0
"""The readiness JSON, contract 1 (boxmunge.readiness_contract).

`upgrade-readiness --json` of every release from 0.11.8 on prints this
shape, and an older release's upgrade check parses it: the fixture is the
contract, and changing it means contract 2.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from boxmunge.readiness_contract import (
    CONTRACT_VERSION, ContractError, Finding, ProjectReadiness, Readiness, parse, to_json,
)

FIXTURE = Path(__file__).parent / "fixtures" / "readiness_contract_v1.json"

SAMPLE = Readiness(
    release="0.12.0", installed="0.11.8",
    box=(Finding("box.compose_version", "block", "before",
                 "Docker Compose 2.30.0 is older than 2.35.0",
                 "as root: apt-get install --only-upgrade docker-compose-plugin"),),
    projects=(
        ProjectReadiness("app", (Finding(
            "project.compose", "todo", "before",
            "app: would be refused by this release's compose validator",
            "fix compose.yml as the message says, then prod-deploy app"),)),
        ProjectReadiness("shop", ()),
    ),
)


def _doc() -> dict:
    return json.loads(json.dumps(to_json(SAMPLE)))


def test_round_trip() -> None:
    assert parse(to_json(SAMPLE)) == SAMPLE
    assert parse(_doc()) == SAMPLE


def test_snapshot_matches_fixture() -> None:
    """The fixture is contract 1. If this fails, the change breaks every
    release that parses this one's output: that is contract 2."""
    text = json.dumps(to_json(SAMPLE), sort_keys=True, indent=2) + "\n"
    assert text == FIXTURE.read_text()
    assert CONTRACT_VERSION == 1


def _set(path: tuple, value: object):
    def mutate(doc: dict) -> None:
        target = doc
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return mutate


def _drop(path: tuple):
    def mutate(doc: dict) -> None:
        target = doc
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]
    return mutate


@pytest.mark.parametrize("mutate", [
    _set(("contract",), 2),
    _set(("contract",), "1"),
    _set(("contract",), True),
    _set(("contract",), 1.0),
    _drop(("contract",)),
    _set(("release",), "0.12"),
    _set(("release",), 12),
    _set(("installed",), "0.11.8+abc1234"),
    _set(("installed",), None),
    _set(("result",), "cant_verify"),
    _set(("result",), "pass"),                     # disagrees with the block finding
    _set(("box",), {}),
    _set(("box", 0, "severity"), "info"),
    _set(("box", 0, "severity"), "BLOCK"),
    _set(("box", 0, "when"), "during"),
    _set(("box", 0, "message"), 7),
    _set(("box", 0, "remedy"), None),
    _set(("box", 0, "id"), ""),
    _drop(("box", 0, "remedy")),
    _set(("box", 0), "box.docker"),
    _set(("projects",), None),
    _set(("projects", 0, "name"), 3),
    _set(("projects", 0, "name"), ""),
    _set(("projects", 0, "result"), "maybe"),
    _set(("projects", 0, "findings"), "none"),
    _set(("projects", 1, "result"), "blocked"),    # no block finding
    _drop(("projects", 0, "findings")),
])
def test_parse_rejects_contract_2_unknown_severity_wrong_types(mutate) -> None:
    doc = _doc()
    mutate(doc)
    assert json.dumps(doc) != json.dumps(_doc()), "the mutation must change the document"
    with pytest.raises(ContractError):
        parse(doc)


@pytest.mark.parametrize("doc", [None, [], "readiness", 1])
def test_parse_rejects_a_non_object(doc) -> None:
    with pytest.raises(ContractError):
        parse(doc)


def test_parse_ignores_unknown_keys() -> None:
    doc = _doc()
    doc["later"] = {"anything": [1, 2]}
    doc["box"][0]["detail"] = "ignored"
    doc["projects"][0]["kind"] = "git"
    doc["projects"][0]["findings"][0]["refs"] = ["#1"]
    assert parse(doc) == SAMPLE


def _finding(severity: str) -> Finding:
    return Finding("project.validate", severity, "before", "m", "r")


def test_result_is_blocked_iff_any_block() -> None:
    todo, block = _finding("todo"), _finding("block")
    assert ProjectReadiness("a", ()).result == "pass"
    assert ProjectReadiness("a", (todo, todo)).result == "pass"
    assert ProjectReadiness("a", (todo, block)).result == "blocked"
    clean = ProjectReadiness("a", (todo,))
    assert Readiness("0.12.0", "0.11.8", (), (clean,)).result == "pass"
    assert Readiness("0.12.0", "0.11.8", (block,), (clean,)).result == "blocked"
    assert Readiness("0.12.0", "0.11.8", (todo,),
                     (clean, ProjectReadiness("b", (block,)))).result == "blocked"


def test_a_finding_outside_the_contract_cannot_be_made() -> None:
    """evaluate() can never print what parse() would refuse."""
    for bad in (("x", "info", "before"), ("x", "todo", "during"), ("", "todo", "before")):
        with pytest.raises(ContractError):
            Finding(*bad, "m", "r")
    with pytest.raises(ContractError):
        ProjectReadiness("", ())
    with pytest.raises(ContractError):
        Readiness("0.12", "0.11.8", (), ())


def test_to_json_is_the_documented_shape() -> None:
    doc = to_json(SAMPLE)
    assert list(doc) == ["contract", "release", "installed", "result", "box", "projects"]
    assert doc["result"] == "blocked" and doc["projects"][1] == {
        "name": "shop", "result": "pass", "findings": []}
    assert list(doc["box"][0]) == ["id", "severity", "when", "message", "remedy"]
    assert copy.deepcopy(doc) == json.loads(json.dumps(doc))
