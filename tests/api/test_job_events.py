# SPDX-License-Identifier: Apache-2.0
"""The job event log writer."""
from __future__ import annotations

import json
import os
import stat
import threading

import pytest

from boxmunge.api import job_events
from boxmunge.api.job_events import MAX_EVENT_MESSAGE, EventLog
from boxmunge.api.jobs import EVENT_SCHEMA
from boxmunge.api.schema import validate
from boxmunge.state import StateError

JOB_ID = "01J" + "B" * 23


def _events(paths) -> list[dict]:
    text = (paths.jobs_dir / f"{JOB_ID}.events.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines()]


@pytest.fixture
def jobs_dir(paths):
    paths.jobs_dir.mkdir(parents=True)
    return paths.jobs_dir


def test_each_kind_of_event_is_written_valid(paths, jobs_dir) -> None:
    log = EventLog(paths, JOB_ID)
    assert log.state("running") == 1
    assert log.step("pull", "started") == 2
    assert log.step("pull", "failed", "no such image") == 3
    assert log.log("hello") == 4
    log.close()
    events = _events(paths)
    assert all(validate(EVENT_SCHEMA, e) == [] for e in events)
    assert [(e["type"], e.get("state"), e.get("step"), e.get("status"), e.get("message"))
            for e in events] == [
        ("state", "running", None, None, None),
        ("step", None, "pull", "started", None),
        ("step", None, "pull", "failed", "no such image"),
        ("log", None, None, None, "hello"),
    ]
    mode = stat.S_IMODE((jobs_dir / f"{JOB_ID}.events.jsonl").stat().st_mode)
    assert mode == 0o640


def test_an_event_outside_the_schema_is_refused(paths, jobs_dir) -> None:
    log = EventLog(paths, JOB_ID)
    with pytest.raises(ValueError, match="status"):
        log.step("pull", "half-done")
    log.close()
    assert (jobs_dir / f"{JOB_ID}.events.jsonl").read_text() == ""


def test_seq_resumes_after_existing_lines(paths, jobs_dir) -> None:
    first = EventLog(paths, JOB_ID)
    first.log("one")
    first.log("two")
    first.close()
    second = EventLog(paths, JOB_ID)
    assert second.log("three") == 3
    second.close()
    assert [e["seq"] for e in _events(paths)] == [1, 2, 3]


def test_a_corrupt_last_line_is_reported_not_renumbered(paths, jobs_dir) -> None:
    (jobs_dir / f"{JOB_ID}.events.jsonl").write_text('{"seq": 1, "ts"\n')
    with pytest.raises(StateError, match="events.jsonl"):
        EventLog(paths, JOB_ID)


def test_concurrent_writers_get_unique_increasing_seqs(paths, jobs_dir) -> None:
    log = EventLog(paths, JOB_ID)
    seqs: list[int] = []
    guard = threading.Lock()

    def write(n: int) -> None:
        for i in range(50):
            seq = log.log(f"thread {n} line {i}")
            with guard:
                seqs.append(seq)

    threads = [threading.Thread(target=write, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log.close()
    assert sorted(seqs) == list(range(1, 401))
    assert [e["seq"] for e in _events(paths)] == list(range(1, 401))


def test_event_log_refuses_a_symlinked_events_file(paths, jobs_dir, tmp_path) -> None:
    target = tmp_path / "elsewhere.jsonl"
    target.write_text("")
    (jobs_dir / f"{JOB_ID}.events.jsonl").symlink_to(target)
    with pytest.raises(StateError, match="symlink"):
        EventLog(paths, JOB_ID)
    assert target.read_text() == ""


def test_long_message_is_cut_and_says_how_much(paths, jobs_dir) -> None:
    log = EventLog(paths, JOB_ID)
    log.log("x" * (MAX_EVENT_MESSAGE + 123))
    log.close()
    message = _events(paths)[0]["message"]
    assert message == "x" * MAX_EVENT_MESSAGE + "…(123 more characters)"


def test_an_existing_file_is_set_to_0640(paths, jobs_dir) -> None:
    path = jobs_dir / f"{JOB_ID}.events.jsonl"
    path.write_text("")
    path.chmod(0o600)
    EventLog(paths, JOB_ID).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_a_failed_handover_does_not_leak_the_descriptor(paths, jobs_dir, monkeypatch) -> None:
    def refuse(_fd: int, _what: str) -> None:
        raise OSError("chown refused")

    monkeypatch.setattr(job_events, "fchown_deploy", refuse)
    before = len(os.listdir("/dev/fd"))
    with pytest.raises(OSError, match="chown refused"):
        EventLog(paths, JOB_ID)
    assert len(os.listdir("/dev/fd")) == before
