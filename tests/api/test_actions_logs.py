# SPDX-License-Identifier: Apache-2.0
"""project.logs and oplog.query."""
from __future__ import annotations

import json

import pytest

from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.docker import DockerError
from tests.api.fakes import StubHost, make_invoker

WEBUI = Principal.plugin("webui", Tier.OBSERVE)


def _call(paths, name, params, host=None):
    invoker = make_invoker(paths, host=host or FixtureHost(paths))
    return invoker.invoke(name, params, WEBUI).data


def _error(paths, name, params, host=None) -> ActionError:
    with pytest.raises(ActionError) as excinfo:
        _call(paths, name, params, host)
    return excinfo.value


def test_logs_for_one_service(fixture_paths) -> None:
    logs = _call(fixture_paths, "project.logs", {"project": "shop", "service": "web", "tail": 5})
    assert (logs["project"], logs["service"], logs["tail"]) == ("shop", "web", 5)
    assert len(logs["lines"]) == 5
    assert all(line.startswith("shop-web-1  | ") for line in logs["lines"])


def test_logs_default_to_every_service_and_100_lines(fixture_paths) -> None:
    host = StubHost(logs={"shop": "a\nb\n"})
    logs = _call(fixture_paths, "project.logs", {"project": "shop"}, host)
    assert logs == {"project": "shop", "service": None, "tail": 100, "lines": ["a", "b"]}
    assert host.log_calls == [("shop", None, 100)]


def test_unknown_service_is_not_found_before_docker_is_asked(fixture_paths) -> None:
    host = StubHost(logs={"shop": "unused"})
    error = _error(fixture_paths, "project.logs", {"project": "shop", "service": "db"}, host)
    assert error.code is ErrorCode.NOT_FOUND
    assert "Its services: web, worker" in error.message
    assert host.log_calls == []


def test_docker_failure_is_unavailable(fixture_paths) -> None:
    host = StubHost(logs={"shop": DockerError("Cannot connect to the Docker daemon")})
    error = _error(fixture_paths, "project.logs", {"project": "shop"}, host)
    assert error.code is ErrorCode.UNAVAILABLE
    assert "Cannot connect" in error.message


@pytest.mark.parametrize("tail", [True, 0, 1001, 2.5, "10"])
def test_tail_must_be_a_whole_number_in_range(fixture_paths, tail) -> None:
    error = _error(fixture_paths, "project.logs", {"project": "shop", "tail": tail})
    assert error.code is ErrorCode.INVALID_PARAMS


def test_oplog_filters_by_level_and_project(fixture_paths) -> None:
    errors = _call(fixture_paths, "oplog.query", {"level": "error"})["entries"]
    assert [(e["component"], e["project"]) for e in errors] == [
        ("backup", "wiki"), ("health", "wiki")]
    shop = _call(fixture_paths, "oplog.query", {"project": "shop"})["entries"]
    assert {e["project"] for e in shop} == {"shop"}


def test_oplog_detail_is_compact_json_or_null(fixture_paths) -> None:
    entries = _call(fixture_paths, "oplog.query", {})["entries"]
    nightly = next(e for e in entries if e["msg"] == "Nightly backups complete")
    assert nightly["detail"] is None and nightly["project"] is None
    quarantine = next(e for e in entries if e["component"] == "cve")
    assert json.loads(quarantine["detail"]) == {"cve_id": "CVE-2026-32003"}


def test_oplog_since_and_tail(fixture_paths) -> None:
    recent = _call(fixture_paths, "oplog.query", {"since": "2h"})["entries"]
    assert [e["msg"] for e in recent] == ["Staged", "Smoke failing: GET /health returned 503"]
    assert len(_call(fixture_paths, "oplog.query", {"tail": 3})["entries"]) == 3


@pytest.mark.parametrize("params", [{"since": "5x"}, {"since": "1h\n"}, {"level": "fatal"}])
def test_oplog_bad_filters_are_invalid(fixture_paths, params) -> None:
    assert _error(fixture_paths, "oplog.query", params).code is ErrorCode.INVALID_PARAMS


def test_oplog_line_that_is_not_an_entry_fails_naming_the_log(fixture_paths) -> None:
    with fixture_paths.log_file.open("a") as log:
        log.write('["not", "an", "entry"]\n')
    error = _error(fixture_paths, "oplog.query", {})
    assert error.code is ErrorCode.FAILED
    assert str(fixture_paths.log_file) in error.message


def test_oplog_line_that_is_not_json_fails_naming_the_line(fixture_paths) -> None:
    """A torn line must not vanish from the query result unremarked."""
    lines = len(fixture_paths.log_file.read_text().splitlines())
    with fixture_paths.log_file.open("a") as log:
        log.write('{"ts": "2026-10-16T00:00:00Z", "lev\n')
    error = _error(fixture_paths, "oplog.query", {})
    assert error.code is ErrorCode.FAILED
    assert f"{fixture_paths.log_file}:{lines + 1}" in error.message


@pytest.mark.parametrize("since", ["999999d", "3651d", "87601h"])
def test_since_reaching_back_more_than_ten_years_is_invalid(fixture_paths, since) -> None:
    error = _error(fixture_paths, "oplog.query", {"since": since})
    assert error.code is ErrorCode.INVALID_PARAMS
    assert "at most 3650 days" in error.message


def test_since_of_exactly_ten_years_is_served(fixture_paths) -> None:
    assert len(_call(fixture_paths, "oplog.query", {"since": "3650d"})["entries"]) > 0
