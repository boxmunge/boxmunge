# SPDX-License-Identifier: Apache-2.0
"""Invariants of the full registry, and the handler discipline."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from boxmunge import cli
from boxmunge.api.actions import build_registry
from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.jobs import JobStore
from boxmunge.api.principal import Principal, PrincipalKind, Tier, refusal
from boxmunge.api.schema import schema_types
from tests.api.fakes import make_invoker

REPO = Path(__file__).resolve().parents[2]
API_SRC = REPO / "src" / "boxmunge" / "api"
REGISTRY = build_registry()

PHASE_A_ACTIONS = {
    "platform.info", "status.get", "projects.list", "health.get",
    "project.get", "project.health", "inbox.list",
    "project.logs", "oplog.query",
    "security.summary", "security.project",
    "backups.list", "jobs.list", "job.get", "job.events",
}


def _subschemas(schema: dict, path: str = "$"):
    yield path, schema
    for name, sub in schema.get("properties", {}).items():
        yield from _subschemas(sub, f"{path}.{name}")
    if "items" in schema:
        yield from _subschemas(schema["items"], f"{path}[]")


def test_the_registry_holds_exactly_the_observe_actions() -> None:
    assert {a.name for a in REGISTRY.actions()} == PHASE_A_ACTIONS
    assert {a.tier for a in REGISTRY.actions()} == {Tier.OBSERVE}
    assert not any(a.job or a.locks for a in REGISTRY.actions())


@pytest.mark.parametrize("action", REGISTRY.actions(), ids=lambda a: a.name)
def test_every_object_schema_is_closed(action) -> None:
    for label, schema in (("params", action.params), ("result", action.result)):
        for path, sub in _subschemas(schema):
            # A job record's result is closed by the named action's own
            # result schema, which this same test walks.
            if "object" in schema_types(sub) and "x-result-of-action" not in sub:
                assert sub.get("additionalProperties") is False, f"{label} {path}"


@pytest.mark.parametrize("action", REGISTRY.actions(), ids=lambda a: a.name)
def test_every_cli_name_is_a_real_command(action) -> None:
    assert action.cli is None or action.cli in cli.COMMANDS


@pytest.mark.parametrize("grant", sorted(Tier, key=lambda t: t.rank), ids=lambda t: t.value)
@pytest.mark.parametrize("kind", [PrincipalKind.PLUGIN, PrincipalKind.ASSISTANT])
def test_no_plugin_or_assistant_reaches_govern_or_platform(kind, grant) -> None:
    try:
        principal = Principal(kind, "webui", grant)
    except ValueError:
        return  # the grant itself is refused
    for tier in (Tier.GOVERN, Tier.PLATFORM):
        for agent_allowed in (False, True):
            assert refusal(principal, tier, agent_allowed=agent_allowed) is not None


def test_catalog_is_json(paths) -> None:
    catalog = make_invoker(paths).catalog(Principal.plugin("webui", Tier.OBSERVE))
    assert {entry["name"] for entry in json.loads(json.dumps(catalog))} == PHASE_A_ACTIONS


def _forbidden_calls(path: Path) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in ("print", "exit", "quit"):
            found.append(f"{path.name}:{node.lineno} {func.id}()")
        if (isinstance(func, ast.Attribute) and func.attr == "exit"
                and isinstance(func.value, ast.Name) and func.value.id in ("sys", "os")):
            found.append(f"{path.name}:{node.lineno} {func.value.id}.exit()")
    return found


def test_api_code_never_prints_or_exits() -> None:
    modules = [p for p in API_SRC.rglob("*.py") if p.name != "apid.py"]
    assert len(modules) > 10
    assert [call for module in modules for call in _forbidden_calls(module)] == []


def _sweep_calls(paths) -> list[tuple[str, dict]]:
    job_id = JobStore(paths).recent()[0]["id"]
    return [
        ("platform.info", {}), ("status.get", {}), ("projects.list", {}), ("health.get", {}),
        ("project.get", {"project": "shop"}), ("project.get", {"project": "newapp"}),
        ("project.health", {"project": "wiki"}),
        ("inbox.list", {}),
        ("project.logs", {"project": "shop", "service": "worker", "tail": 3}),
        ("oplog.query", {"level": "error"}),
        ("security.summary", {}), ("security.project", {"project": "billing"}),
        ("backups.list", {"project": "shop"}),
        ("jobs.list", {}), ("job.get", {"id": job_id}), ("job.events", {"id": job_id}),
    ]


def test_every_action_runs_silently_against_the_fixture(fixture_paths, capfd) -> None:
    invoker = make_invoker(fixture_paths, host=FixtureHost(fixture_paths))
    calls = _sweep_calls(fixture_paths)
    assert {name for name, _ in calls} == PHASE_A_ACTIONS
    for name, params in calls:
        invoker.invoke(name, params, Principal.plugin("webui", Tier.OBSERVE))
    assert capfd.readouterr() == ("", "")


_TIMESTAMPISH = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z")


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def test_every_timestamp_any_action_returns_is_utc_with_a_z(fixture_paths) -> None:
    """One format for every action: ISO 8601, UTC, trailing Z."""
    invoker = make_invoker(fixture_paths, host=FixtureHost(fixture_paths))
    bad = []
    for name, params in _sweep_calls(fixture_paths):
        data = invoker.invoke(name, params, Principal.plugin("webui", Tier.OBSERVE)).data
        if name == "project.logs":
            continue  # container log lines are text, timestamps inside them are not fields
        bad += [(name, s) for s in _strings(data)
                if _TIMESTAMPISH.match(s) and not _TIMESTAMP.fullmatch(s)]
    assert bad == []


def _result_of_action_sites(schema: dict, path: str = "$", parent: dict | None = None,
                            name: str | None = None):
    if "x-result-of-action" in schema:
        yield path, name, parent
    for prop, sub in schema.get("properties", {}).items():
        yield from _result_of_action_sites(sub, f"{path}.{prop}", schema, prop)
    if "items" in schema:
        yield from _result_of_action_sites(schema["items"], f"{path}[]", schema, None)


def test_result_of_action_appears_only_on_job_records() -> None:
    sites = {}
    for action in REGISTRY.actions():
        for label, schema in (("params", action.params), ("result", action.result)):
            for path, name, parent in _result_of_action_sites(schema):
                assert name == "result" and "action" in parent["properties"], (action.name, path)
                sites.setdefault(action.name, []).append(f"{label} {path}")
    assert sites == {"job.get": ["result $.result"], "jobs.list": ["result $.jobs[].result"]}
