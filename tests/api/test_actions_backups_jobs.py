# SPDX-License-Identifier: Apache-2.0
"""backups.list, jobs.list, job.get and job.events."""
from __future__ import annotations

import pytest

from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError, ErrorCode
from tests.api.fakes import make_invoker

WEBUI = Principal.plugin("webui", Tier.OBSERVE)
UNKNOWN_JOB = "01J" + "Z" * 23


def _call(paths, name, params=None):
    return make_invoker(paths, host=FixtureHost(paths)).invoke(name, params or {}, WEBUI).data


def _error(paths, name, params) -> ActionError:
    with pytest.raises(ActionError) as excinfo:
        _call(paths, name, params)
    return excinfo.value


def test_backups_newest_first_with_kind_and_time(fixture_paths) -> None:
    result = _call(fixture_paths, "backups.list", {"project": "shop"})
    assert [s["kind"] for s in result["snapshots"]] == ["predeploy", "nightly", "manual"]
    first = result["snapshots"][0]
    assert first["name"].endswith("-predeploy.tar.gz.age") and first["size"] == 4096
    assert first["taken_at"].endswith("Z") and "T" in first["taken_at"]


def test_snapshot_with_an_unknown_name_is_listed_without_kind(fixture_paths) -> None:
    odd = fixture_paths.project_backups("shop") / "shop-handmade.tar.gz.age"
    odd.write_bytes(b"x")
    names = {s["name"]: s for s in _call(fixture_paths, "backups.list",
                                         {"project": "shop"})["snapshots"]}
    assert names["shop-handmade.tar.gz.age"]["kind"] is None
    assert names["shop-handmade.tar.gz.age"]["taken_at"] is None


def test_project_without_backups(fixture_paths) -> None:
    assert _call(fixture_paths, "backups.list", {"project": "newapp"}) == {
        "project": "newapp", "snapshots": []}
    assert _error(fixture_paths, "backups.list",
                  {"project": "ghost"}).code is ErrorCode.NOT_FOUND


def test_jobs_list_get_and_events(fixture_paths) -> None:
    jobs = _call(fixture_paths, "jobs.list")["jobs"]
    assert [j["action"] for j in jobs] == ["project.deploy", "project.backup"]
    assert [j["action"] for j in _call(fixture_paths, "jobs.list",
                                       {"project": "wiki"})["jobs"]] == ["project.backup"]
    assert len(_call(fixture_paths, "jobs.list", {"limit": 1})["jobs"]) == 1
    deploy = jobs[0]
    assert _call(fixture_paths, "job.get", {"id": deploy["id"]}) == deploy
    events = _call(fixture_paths, "job.events", {"id": deploy["id"], "after": 5})
    assert [e["seq"] for e in events["events"]] == [6, 7]
    assert events["events"][-1] == {**events["events"][-1], "type": "state",
                                    "state": "succeeded"}


def test_failed_job_carries_its_error(fixture_paths) -> None:
    backup = _call(fixture_paths, "jobs.list", {"project": "wiki"})["jobs"][0]
    assert backup["state"] == "failed" and "pg_dump" in backup["error"]["message"]


def test_unknown_and_malformed_job_ids(fixture_paths) -> None:
    assert _error(fixture_paths, "job.get", {"id": UNKNOWN_JOB}).code is ErrorCode.NOT_FOUND
    assert _error(fixture_paths, "job.events",
                  {"id": UNKNOWN_JOB}).code is ErrorCode.NOT_FOUND
    assert _error(fixture_paths, "job.get",
                  {"id": "../../etc/passwd"}).code is ErrorCode.INVALID_PARAMS
