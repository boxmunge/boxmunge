# SPDX-License-Identifier: Apache-2.0
"""The read side of the job store."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from boxmunge.api.jobs import EVENT_SCHEMA, JOB_SCHEMA, JobStore
from boxmunge.api.schema import INTEGER, check_schema, obj
from boxmunge.state import StateError
from tests.api.fakes import registry_results


def _id(n: int) -> str:
    return "01J" + "A" * 22 + str(n)


def _record(n: int, **fields) -> dict:
    record = {
        "id": _id(n), "action": "project.deploy", "principal": "plugin:webui",
        "project": "shop", "state": "succeeded",
        "created_at": f"2026-10-14T0{n}:00:00Z",
        "started_at": f"2026-10-14T0{n}:00:05Z",
        "finished_at": f"2026-10-14T0{n}:01:30Z", "error": None, "result": None,
    }
    record.update(fields)
    return record


def _write(directory, record) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{record['id']}.json").write_text(json.dumps(record))


def test_schemas_are_inside_the_subset() -> None:
    check_schema(JOB_SCHEMA)
    check_schema(EVENT_SCHEMA)


def test_get_finds_finished_and_unfinished_jobs(paths) -> None:
    _write(paths.jobs_dir, _record(1))
    _write(paths.jobs_queue, _record(2, state="running", finished_at=None))
    store = JobStore(paths, result_schemas=registry_results)
    assert store.get(_id(1))["state"] == "succeeded"
    assert store.get(_id(2))["state"] == "running"
    assert store.get(_id(3)) is None


def test_recent_is_newest_first_filtered_and_limited(paths) -> None:
    _write(paths.jobs_dir, _record(1))
    _write(paths.jobs_dir, _record(2, project="wiki"))
    _write(paths.jobs_queue, _record(3, state="queued", started_at=None, finished_at=None))
    (paths.jobs_dir / ".tmp-123.json").write_text("{")
    store = JobStore(paths, result_schemas=registry_results)
    assert [j["id"] for j in store.recent().jobs] == [_id(3), _id(2), _id(1)]
    assert [j["id"] for j in store.recent(project="shop").jobs] == [_id(3), _id(1)]
    assert [j["id"] for j in store.recent(limit=1).jobs] == [_id(3)]
    assert store.recent().unreadable == []


def test_the_terminal_copy_wins_while_a_job_is_being_finished(paths) -> None:
    _write(paths.jobs_dir, _record(1))
    _write(paths.jobs_queue, _record(1, state="running", finished_at=None))
    store = JobStore(paths, result_schemas=registry_results)
    assert [j["state"] for j in store.recent().jobs] == ["succeeded"]
    assert store.get(_id(1))["state"] == "succeeded"


def test_a_job_finishing_between_the_two_scans_is_never_missed(paths, monkeypatch) -> None:
    """The finish step links the record into jobs/ and then unlinks it from
    queue/. Scanning queue/ first means a job that moves mid-listing is
    found in jobs/ afterwards."""
    _write(paths.jobs_queue, _record(1, state="running", finished_at=None))
    real_glob = Path.glob

    def glob_then_finish(self, pattern):
        found = list(real_glob(self, pattern))
        if self == paths.jobs_queue and (paths.jobs_queue / f"{_id(1)}.json").exists():
            _write(paths.jobs_dir, _record(1))
            (paths.jobs_queue / f"{_id(1)}.json").unlink()
        return iter(found)

    monkeypatch.setattr(Path, "glob", glob_then_finish)
    jobs = JobStore(paths, result_schemas=registry_results).recent().jobs
    assert [(j["id"], j["state"]) for j in jobs] == [(_id(1), "succeeded")]


def test_a_record_that_vanishes_before_it_is_read_is_absent(paths) -> None:
    paths.jobs_queue.mkdir(parents=True)
    (paths.jobs_queue / f"{_id(1)}.json").symlink_to(paths.jobs_queue / "gone.json")
    store = JobStore(paths, result_schemas=registry_results)
    assert store.recent().jobs == [] and store.recent().unreadable == []
    assert store.get(_id(1)) is None


def test_a_record_without_its_result_field_is_corrupt(paths) -> None:
    record = _record(1)
    del record["result"]
    _write(paths.jobs_dir, record)
    with pytest.raises(StateError, match="missing required property 'result'"):
        JobStore(paths, result_schemas=registry_results).get(_id(1))


def test_no_job_directories_means_no_jobs(paths) -> None:
    assert JobStore(paths, result_schemas=registry_results).recent().jobs == []


@pytest.mark.parametrize("record,message", [
    (_record(1, state="done"), "$.state: must be one of"),
    (_record(1, extra=1), "unexpected property 'extra'"),
])
def test_corrupt_records_are_reported(paths, record, message) -> None:
    _write(paths.jobs_dir, record)
    with pytest.raises(StateError, match="is corrupt") as excinfo:
        JobStore(paths, result_schemas=registry_results).get(_id(1))
    assert message in str(excinfo.value)


def test_record_under_the_wrong_name_is_corrupt(paths) -> None:
    paths.jobs_dir.mkdir(parents=True)
    (paths.jobs_dir / f"{_id(2)}.json").write_text(json.dumps(_record(1)))
    with pytest.raises(StateError, match="holds the id"):
        JobStore(paths, result_schemas=registry_results).get(_id(2))


def test_events_after_a_sequence_number(paths) -> None:
    paths.jobs_dir.mkdir(parents=True)
    lines = [
        {"seq": 1, "ts": "2026-10-14T00:00:01Z", "type": "state", "state": "running"},
        {"seq": 2, "ts": "2026-10-14T00:00:02Z", "type": "step", "step": "build", "status": "started"},
        {"seq": 3, "ts": "2026-10-14T00:00:03Z", "type": "log", "message": "Pulling images"},
    ]
    (paths.jobs_dir / f"{_id(1)}.events.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines))
    store = JobStore(paths, result_schemas=registry_results)
    assert [e["seq"] for e in store.events(_id(1))] == [1, 2, 3]
    assert [e["seq"] for e in store.events(_id(1), after=1)] == [2, 3]
    assert store.events(_id(2)) == []


@pytest.mark.parametrize("line,message", [
    ("{not json", "not JSON"),
    ('{"seq": 0, "ts": "2026-10-14T00:00:00Z", "type": "log"}', "below minimum 1"),
    ('{"seq": 1, "ts": "2026-10-14T00:00:00Z", "type": "shout"}', "must be one of"),
])
def test_corrupt_event_lines_are_reported(paths, line, message) -> None:
    paths.jobs_dir.mkdir(parents=True)
    (paths.jobs_dir / f"{_id(1)}.events.jsonl").write_text(line + "\n")
    with pytest.raises(StateError, match=message):
        JobStore(paths, result_schemas=registry_results).events(_id(1))


def test_an_unreadable_record_is_listed_not_raised(paths) -> None:
    _write(paths.jobs_dir, _record(1))
    _write(paths.jobs_dir, _record(2, state="done"))
    listing = JobStore(paths, result_schemas=registry_results).recent()
    assert [j["id"] for j in listing.jobs] == [_id(1)]
    assert [u["id"] for u in listing.unreadable] == [_id(2)]
    assert str(paths.jobs_dir / f"{_id(2)}.json") in listing.unreadable[0]["problem"]


def test_a_record_nested_too_deeply_is_corrupt_naming_the_file(paths) -> None:
    paths.jobs_dir.mkdir(parents=True)
    path = paths.jobs_dir / f"{_id(1)}.json"
    path.write_text('{"id": ' + "[" * 100000 + "]" * 100000 + "}")
    with pytest.raises(StateError, match="nested too deeply") as excinfo:
        JobStore(paths, result_schemas=registry_results).get(_id(1))
    assert str(path) in str(excinfo.value)


def test_a_non_null_result_is_checked_against_its_action(paths) -> None:
    _write(paths.jobs_dir, _record(1, result={"count": 3}))
    with pytest.raises(StateError, match="action project.deploy is no longer registered"):
        JobStore(paths, result_schemas=registry_results).get(_id(1))
    schemas = {"project.deploy": obj({"count": INTEGER})}.get
    assert JobStore(paths, result_schemas=schemas).get(_id(1))["result"] == {"count": 3}
    _write(paths.jobs_dir, _record(1, result={"count": "3"}))
    with pytest.raises(StateError, match=r"\$.result.count: expected integer"):
        JobStore(paths, result_schemas=schemas).get(_id(1))
