# SPDX-License-Identifier: Apache-2.0
"""project.logs and oplog.query."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.commands.log_cmd import query_log
from boxmunge.docker import DockerError
from boxmunge.log_rotation import archive_path
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


def _archive(paths, days_ago: int, *msgs: str) -> Path:
    """The rotated archive of the UTC day `days_ago` days back, as the log
    handler leaves it: older than everything in the fixture's active log."""
    when = datetime.now(timezone.utc) - timedelta(days=days_ago)
    path = archive_path(paths.log_file, when.date())
    path.write_text("".join(json.dumps({
        "ts": (when + timedelta(microseconds=i)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "level": "info", "component": "deploy", "project": "shop", "msg": msg,
    }) + "\n" for i, msg in enumerate(msgs)))
    return path


def _msgs(entries) -> list[str]:
    return [e["msg"] for e in entries]


def test_oplog_reads_the_rotated_archives_that_log_reads(fixture_paths) -> None:
    """One reader for the action and the CLI's `log`: a window that reaches
    back past the last rotation returns the archived entries too."""
    _archive(fixture_paths, 6, "six days ago")
    _archive(fixture_paths, 5, "five days ago")
    active = _msgs(_call(fixture_paths, "oplog.query", {"since": "4d"})["entries"])
    week = _call(fixture_paths, "oplog.query", {"since": "7d"})["entries"]
    assert _msgs(week) == ["six days ago", "five days ago", *active]
    assert _msgs(week) == _msgs(query_log(fixture_paths, since="7d", tail=50).entries)
    assert _msgs(_call(fixture_paths, "oplog.query", {"since": "132h"})["entries"]) == [
        "five days ago", *active]
    assert week[0] == {"ts": week[0]["ts"], "level": "info", "component": "deploy",
                       "project": "shop", "msg": "six days ago", "detail": None}


def test_oplog_tail_bounds_the_result_across_archives(fixture_paths) -> None:
    active = _msgs(_call(fixture_paths, "oplog.query", {})["entries"])
    _archive(fixture_paths, 5, *(f"old-{i}" for i in range(1100)))
    default = _msgs(_call(fixture_paths, "oplog.query", {"since": "7d"})["entries"])
    assert len(default) == 50
    assert default == [f"old-{i}" for i in range(1100 - 50 + len(active), 1100)] + active
    assert _msgs(_call(fixture_paths, "oplog.query", {"tail": len(active) + 1})["entries"]) == [
        "old-1099", *active]
    assert len(_call(fixture_paths, "oplog.query", {"tail": 1000})["entries"]) == 1000
    assert _error(fixture_paths, "oplog.query", {"tail": 1001}).code is ErrorCode.INVALID_PARAMS


@pytest.mark.parametrize("line", [
    b'{"ts": "2026-\n', b'["not", "an", "entry"]\n', b'{"msg": "an entry with no ts"}\n',
    b'{"ts": "\xff\xfe"}\n',
], ids=["torn", "not-an-object", "missing-keys", "undecodable"])
def test_oplog_bad_line_in_an_archive_it_reads_fails_naming_the_line(fixture_paths, line) -> None:
    archive = _archive(fixture_paths, 5, "five days ago")
    with archive.open("ab") as log:
        log.write(line)
    error = _error(fixture_paths, "oplog.query", {"since": "7d"})
    assert error.code is ErrorCode.FAILED
    assert f"{archive}:2" in error.message
    # As `log`: an archive the query does not reach is not read.
    assert len(_call(fixture_paths, "oplog.query", {"tail": 3})["entries"]) == 3
    assert len(_call(fixture_paths, "oplog.query", {"since": "2d"})["entries"]) > 3


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "dangling"])
def test_oplog_archive_that_is_a_link_is_refused_not_read_through(
        fixture_paths, tmp_path, kind) -> None:
    """logs/ is deploy-writable: a name there is never read through a link."""
    real = _archive(fixture_paths, 5, "five days ago")
    elsewhere = real.rename(tmp_path / "elsewhere")
    if kind == "hardlink":
        os.link(elsewhere, real)
    else:
        real.symlink_to(elsewhere if kind == "symlink" else tmp_path / "gone")
    error = _error(fixture_paths, "oplog.query", {"since": "7d"})
    assert error.code is ErrorCode.FAILED
    assert str(real) in error.message and "not a plain regular file" in error.message


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any mode")
def test_oplog_unreadable_archive_fails_naming_it(fixture_paths) -> None:
    archive = _archive(fixture_paths, 5, "five days ago")
    archive.chmod(0)
    error = _error(fixture_paths, "oplog.query", {"since": "7d"})
    assert error.code is ErrorCode.FAILED
    assert str(archive) in error.message and "Permission denied" in error.message
