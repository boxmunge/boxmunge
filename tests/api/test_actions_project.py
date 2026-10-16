# SPDX-License-Identifier: Apache-2.0
"""project.get, project.health and inbox.list."""
from __future__ import annotations

import pytest

from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError, ErrorCode
from tests.api.fakes import StubHost, make_invoker

WEBUI = Principal.plugin("webui", Tier.OBSERVE)


def _call(paths, name, params, host=None):
    invoker = make_invoker(paths, host=host or FixtureHost(paths))
    return invoker.invoke(name, params, WEBUI).data


def _code(paths, name, params, host=None) -> ActionError:
    with pytest.raises(ActionError) as excinfo:
        _call(paths, name, params, host)
    return excinfo.value


def test_running_project(fixture_paths) -> None:
    shop = _call(fixture_paths, "project.get", {"project": "shop"})
    assert shop["lifecycle"] == "running"
    assert shop["health"]["status"] == "ok" and shop["health"]["failure_reason"] is None
    assert shop["deploy"]["current_ref"].startswith("shop-")
    assert len(shop["deploy"]["history"]) == 1
    assert shop["staging"] == {"active": False, "ref": None}
    assert shop["paused"] is None and shop["quarantine"] is None


def test_paused_quarantined_staged_and_pre_registered(fixture_paths) -> None:
    blog = _call(fixture_paths, "project.get", {"project": "blog"})
    assert blog["lifecycle"] == "paused"
    assert blog["paused"]["reason"] == "Content freeze until the redesign ships"
    billing = _call(fixture_paths, "project.get", {"project": "billing"})
    assert billing["lifecycle"] == "quarantined"
    assert billing["quarantine"]["cve_id"] == "CVE-2026-32003"
    assert billing["quarantine"]["action_complete"] is True
    wiki = _call(fixture_paths, "project.get", {"project": "wiki"})
    assert wiki["staging"]["active"] is True and wiki["staging"]["ref"].startswith("wiki-")
    assert wiki["health"]["consecutive_failures"] == 3
    newapp = _call(fixture_paths, "project.get", {"project": "newapp"})
    assert newapp["lifecycle"] == "pre_registered"
    assert newapp["deploy"] == {"current_ref": None, "deployed_at": None, "history": []}


def test_monitor_stopped_project(fixture_paths) -> None:
    fixture_paths.project_health_state("shop").write_text(
        '{"status": "critical_stopped", "stopped_at": "2999-01-01T00:00:00+00:00"}')
    assert _call(fixture_paths, "project.get", {"project": "shop"})["lifecycle"] == \
        "monitor_stopped"


@pytest.mark.parametrize("name", ["shop\n", "../shop", "Shop", ""])
def test_names_outside_the_pattern_are_invalid(fixture_paths, name) -> None:
    error = _code(fixture_paths, "project.get", {"project": name})
    assert error.code is ErrorCode.INVALID_PARAMS


@pytest.mark.parametrize("name", ["caddy", "system", "shop-staging"])
def test_reserved_names_are_invalid_not_looked_up(fixture_paths, name) -> None:
    (fixture_paths.projects / name).mkdir()
    error = _code(fixture_paths, "project.get", {"project": name})
    assert error.code is ErrorCode.INVALID_PARAMS
    assert "reserved" in error.message


def test_unknown_project_is_not_found(fixture_paths) -> None:
    error = _code(fixture_paths, "project.get", {"project": "ghost"})
    assert error.code is ErrorCode.NOT_FOUND
    assert "projects.list" in error.message


@pytest.mark.parametrize("state_file,content", [
    ("project_health_state", "{not json"),
    ("project_paused_state", "{not json"),
    ("project_paused_state", "[]"),
    ("project_paused_state", "{}"),
])
def test_corrupt_state_fails_naming_the_file(fixture_paths, state_file, content) -> None:
    path = getattr(fixture_paths, state_file)("blog")
    path.write_text(content)
    error = _code(fixture_paths, "project.get", {"project": "blog"})
    assert error.code is ErrorCode.FAILED
    assert str(path) in error.message


def test_project_health_reports_the_check(fixture_paths) -> None:
    wiki = _call(fixture_paths, "project.health", {"project": "wiki"})
    assert wiki == {"project": "wiki", "exit_code": 1, "status": "warning",
                    "smoke": {"status": "warning", "message": "GET /health returned 503"}}


def test_project_health_needs_a_deployed_project(fixture_paths) -> None:
    error = _code(fixture_paths, "project.health", {"project": "newapp"})
    assert error.code is ErrorCode.CONFLICT


def test_project_health_check_errors_fail(fixture_paths) -> None:
    host = StubHost(checks={"shop": {"project": "shop", "exit_code": 1,
                                     "error": "Manifest is not valid YAML"}})
    error = _code(fixture_paths, "project.health", {"project": "shop"}, host)
    assert error.code is ErrorCode.FAILED and "not valid YAML" in error.message


def test_inbox_list(fixture_paths) -> None:
    bundles = _call(fixture_paths, "inbox.list", {})["bundles"]
    assert [b["project"] for b in bundles] == ["shop", "wiki"]
    assert all(b["size"] == 2048 for b in bundles)
    only_wiki = _call(fixture_paths, "inbox.list", {"project": "wiki"})["bundles"]
    assert [b["project"] for b in only_wiki] == ["wiki"]
