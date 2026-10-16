# SPDX-License-Identifier: Apache-2.0
"""backups.list, jobs.list, job.get and job.events."""
from __future__ import annotations

import json

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


def _job_file(paths, action: str):
    """The fixture's job record for *action*, and the record itself."""
    for path in paths.jobs_dir.glob("*.json"):
        record = json.loads(path.read_text())
        if record["action"] == action:
            return path, record
    raise AssertionError(f"no fixture job for {action}")


def _rewrite(path, record, **changes) -> str:
    record.update(changes)
    path.write_text(json.dumps(record))
    return record["id"]


def test_a_job_result_is_served_when_it_matches_its_action(fixture_paths) -> None:
    path, record = _job_file(fixture_paths, "project.deploy")
    job_id = _rewrite(path, record, action="projects.list", result={"projects": ["shop"]})
    assert _call(fixture_paths, "job.get", {"id": job_id})["result"] == {"projects": ["shop"]}
    listing = _call(fixture_paths, "jobs.list")
    assert job_id in [j["id"] for j in listing["jobs"]] and "unreadable" not in listing


@pytest.mark.parametrize("changes,problem", [
    ({"action": "projects.list", "result": {"projects": "shop"}}, "expected array"),
    ({"result": {"ok": True}}, "action project.deploy is no longer registered"),
    ({"state": "finished"}, "must be one of"),
])
def test_one_bad_job_record_does_not_fail_the_list(fixture_paths, changes, problem) -> None:
    path, record = _job_file(fixture_paths, "project.deploy")
    job_id = _rewrite(path, record, **changes)
    listing = _call(fixture_paths, "jobs.list")
    assert [j["action"] for j in listing["jobs"]] == ["project.backup"]
    assert [u["id"] for u in listing["unreadable"]] == [job_id]
    assert problem in listing["unreadable"][0]["problem"]
    assert str(path) in listing["unreadable"][0]["problem"]
    error = _error(fixture_paths, "job.get", {"id": job_id})
    assert error.code is ErrorCode.FAILED and str(path) in error.message


def test_a_job_record_that_is_not_json_is_unreadable(fixture_paths) -> None:
    path, record = _job_file(fixture_paths, "project.deploy")
    path.write_text("{not json")
    listing = _call(fixture_paths, "jobs.list")
    assert [u["id"] for u in listing["unreadable"]] == [record["id"]]
