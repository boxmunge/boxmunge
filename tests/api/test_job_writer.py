# SPDX-License-Identifier: Apache-2.0
"""The job record's publish, claim and finish: each durable before the next."""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.api import job_writer
from boxmunge.api.jobs import JOB_SCHEMA
from boxmunge.api.schema import INTEGER, obj, validate
from boxmunge.api.worker_identity import WorkerIdentity
from boxmunge.state import StateError

JOB_ID = "01J" + "A" * 23
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
LATER = datetime(2026, 11, 15, 12, 5, tzinfo=timezone.utc)
WORKER = WorkerIdentity("11111111-2222-3333-4444-555555555555", 4242, 987654)


def _record(**fields) -> dict:
    record = job_writer.new_record(JOB_ID, "project.deploy", {"project": "shop", "ref": "v2"},
                                   "plugin:webui", "shop", NOW)
    record.update(fields)
    return record


def _queued(paths) -> Path:
    return paths.jobs_queue / f"{JOB_ID}.json"


def _done(paths) -> Path:
    return paths.jobs_dir / f"{JOB_ID}.json"


def _read(path: Path) -> dict:
    return json.loads(path.read_text())


class _Recorder:
    """Every fsync, link, rename and unlink, named by the directory or file
    it touched, in the order they happened."""

    def __init__(self, paths) -> None:
        self.events: list[tuple[str, str]] = []
        self._dirs = {"queue": paths.jobs_queue, "jobs": paths.jobs_dir}

    def _where(self, path) -> str:
        path = Path(path)
        for name, directory in self._dirs.items():
            if path.parent == directory:
                return f"{name}/{'tmp' if path.name.endswith('.tmp') else path.name}"
        return str(path)

    def _dir_name(self, fd: int) -> str:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            return "file"
        for name, directory in self._dirs.items():
            if directory.exists() and os.stat(directory).st_ino == st.st_ino:
                return f"{name}/"
        return "other/"

    def __enter__(self):
        real = {name: getattr(os, name) for name in ("fsync", "link", "rename", "unlink")}

        def fsync(fd):
            self.events.append(("fsync", self._dir_name(fd)))
            real["fsync"](fd)

        def link(src, dst):
            self.events.append(("link", self._where(dst)))
            real["link"](src, dst)

        def rename(src, dst):
            self.events.append(("rename", self._where(dst)))
            real["rename"](src, dst)

        def unlink(path, *args, **kwargs):
            self.events.append(("unlink", self._where(path)))
            real["unlink"](path, *args, **kwargs)

        self._patches = [patch.object(os, "fsync", fsync), patch.object(os, "link", link),
                         patch.object(os, "rename", rename), patch.object(os, "unlink", unlink)]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()


NAME = f"{JOB_ID}.json"


def test_new_record_is_queued_with_compact_params_and_no_worker() -> None:
    record = _record()
    assert record["state"] == "queued"
    assert record["params"] == '{"project":"shop","ref":"v2"}'
    assert record["worker"] is None
    assert record["started_at"] is None and record["finished_at"] is None
    assert validate(JOB_SCHEMA, record) == []


def test_publish_syncs_file_then_queue_dir_before_returning(paths) -> None:
    with _Recorder(paths) as rec:
        assert job_writer.publish(paths, _record()) is True
    assert rec.events == [
        ("fsync", "file"), ("link", f"queue/{NAME}"), ("fsync", "queue/"),
        ("unlink", "jobs/tmp"), ("fsync", "jobs/"),
    ]
    assert _read(_queued(paths)) == _record()
    assert [p.name for p in paths.jobs_queue.iterdir()] == [NAME]
    assert not list(paths.jobs_dir.glob("*.tmp"))
    st = os.stat(_queued(paths))
    assert stat.S_IMODE(st.st_mode) == 0o640 and st.st_nlink == 1


def test_publish_takes_the_job_lock(paths) -> None:
    held: list[Path] = []
    real = job_writer.exclusive_lock

    def lock(path):
        held.append(path)
        return real(path)

    with patch.object(job_writer, "exclusive_lock", lock):
        job_writer.publish(paths, _record())
    assert held == [paths.job_lock(JOB_ID)]
    assert paths.job_lock(JOB_ID) == paths.jobs_dir / f"{JOB_ID}.lock"


@pytest.mark.parametrize("where", ["queue", "jobs"])
def test_publish_refuses_an_id_already_in_queue_or_jobs(paths, where) -> None:
    existing = _queued(paths) if where == "queue" else _done(paths)
    existing.parent.mkdir(parents=True, exist_ok=True)
    existing.write_text("already here")
    assert job_writer.publish(paths, _record()) is False
    assert existing.read_text() == "already here"
    assert not list(paths.jobs_dir.glob("*.tmp"))
    if where == "jobs":
        assert not _queued(paths).exists()


def test_publish_that_fails_after_its_link_queues_nothing(paths) -> None:
    real = job_writer.fsync_dir

    def fsync_dir(path):
        if Path(path) == paths.jobs_queue:
            raise OSError(5, "Input/output error")
        real(path)

    with patch.object(job_writer, "fsync_dir", fsync_dir), \
            pytest.raises(OSError, match="Input/output error"):
        job_writer.publish(paths, _record())
    assert list(paths.jobs_queue.iterdir()) == []
    assert not list(paths.jobs_dir.glob("*.tmp"))
    assert job_writer.publish(paths, _record()) is True


def test_publish_whose_link_cannot_be_withdrawn_says_the_job_is_queued(paths) -> None:
    def fail(path):
        raise OSError(5, "Input/output error")

    real_unlink = os.unlink

    def unlink(path, *args, **kwargs):
        if Path(path) == _queued(paths):
            raise OSError(30, "Read-only file system")
        real_unlink(path, *args, **kwargs)

    with patch.object(job_writer, "durable_unlink", fail), patch.object(os, "unlink", unlink), \
            pytest.raises(StateError, match="the job is queued and will run"):
        job_writer.publish(paths, _record())
    assert _queued(paths).exists()


def test_publish_refuses_a_record_that_breaks_the_schema(paths) -> None:
    with pytest.raises(ValueError, match="params"):
        job_writer.publish(paths, _record(params={"not": "text"}))
    assert not _queued(paths).exists()


def test_claim_rewrites_running_with_identity_and_syncs_queue(paths) -> None:
    job_writer.publish(paths, _record())
    with _Recorder(paths) as rec:
        claimed = job_writer.claim(paths, JOB_ID, WORKER, LATER)
    assert rec.events == [("fsync", "file"), ("rename", f"queue/{NAME}"), ("fsync", "queue/"),
                          ("fsync", "jobs/")]
    assert claimed["state"] == "running"
    assert claimed["worker"] == WORKER.as_record()
    assert claimed["started_at"] == "2026-11-15T12:05:00Z"
    assert _read(_queued(paths)) == claimed
    assert stat.S_IMODE(os.stat(_queued(paths)).st_mode) == 0o640
    assert not list(paths.jobs_dir.glob("*.tmp"))


def test_claim_of_a_running_or_missing_record_returns_none(paths) -> None:
    assert job_writer.claim(paths, JOB_ID, WORKER, LATER) is None
    job_writer.publish(paths, _record())
    first = job_writer.claim(paths, JOB_ID, WORKER, LATER)
    other = WorkerIdentity(WORKER.boot_id, 99, 1)
    assert job_writer.claim(paths, JOB_ID, other, LATER) is None
    assert _read(_queued(paths)) == first


def test_claim_of_a_corrupt_record_is_a_state_error(paths) -> None:
    _queued(paths).parent.mkdir(parents=True)
    _queued(paths).write_text("{")
    with pytest.raises(StateError, match=str(_queued(paths))):
        job_writer.claim(paths, JOB_ID, WORKER, LATER)


def test_finish_order_is_queue_sync_then_jobs_link_sync_then_unlink_sync(paths) -> None:
    job_writer.publish(paths, _record())
    job_writer.claim(paths, JOB_ID, WORKER, LATER)
    with _Recorder(paths) as rec:
        done = job_writer.finish(paths, JOB_ID, state="succeeded", error=None,
                                 result=None, now=LATER)
    assert rec.events == [
        ("fsync", "file"), ("rename", f"queue/{NAME}"), ("fsync", "queue/"), ("fsync", "jobs/"),
        ("link", f"jobs/{NAME}"), ("fsync", "jobs/"),
        ("unlink", f"queue/{NAME}"), ("fsync", "queue/"),
    ]
    assert done["state"] == "succeeded" and done["finished_at"] == "2026-11-15T12:05:00Z"
    assert done["worker"] == WORKER.as_record()
    assert _read(_done(paths)) == done
    assert list(paths.jobs_queue.iterdir()) == []
    assert os.stat(_done(paths)).st_nlink == 1


def test_finish_records_the_error_of_a_failed_job(paths) -> None:
    job_writer.publish(paths, _record())
    job_writer.claim(paths, JOB_ID, WORKER, LATER)
    error = {"code": "busy", "message": "shop is locked by a backup."}
    done = job_writer.finish(paths, JOB_ID, state="failed", error=error, result=None, now=LATER)
    assert done["error"] == error and _read(_done(paths))["state"] == "failed"


@pytest.mark.parametrize("state", ["queued", "running"])
def test_finish_refuses_a_state_that_is_not_terminal(paths, state) -> None:
    job_writer.publish(paths, _record())
    with pytest.raises(ValueError, match="terminal"):
        job_writer.finish(paths, JOB_ID, state=state, error=None, result=None, now=LATER)


def test_finish_of_a_missing_or_unclaimed_job_is_a_state_error(paths) -> None:
    error = {"code": "x", "message": "y"}
    with pytest.raises(StateError, match="only a running job can, .* holds nothing"):
        job_writer.finish(paths, JOB_ID, state="failed", error=error, result=None, now=LATER)
    job_writer.publish(paths, _record())
    with pytest.raises(StateError, match="holds a queued record"):
        job_writer.finish(paths, JOB_ID, state="failed", error=error, result=None, now=LATER)
    assert _read(_queued(paths))["state"] == "queued"


@pytest.mark.parametrize("state,error,result,message", [
    ("failed", None, None, "needs an error"),
    ("failed", {"code": "x", "message": "y"}, {"n": 1}, "no result"),
    ("succeeded", {"code": "x", "message": "y"}, None, "has no error"),
    ("succeeded", None, {"n": 1}, "only be written with result_schemas"),
])
def test_finish_refuses_an_outcome_that_does_not_add_up(paths, state, error, result,
                                                        message) -> None:
    job_writer.publish(paths, _record())
    job_writer.claim(paths, JOB_ID, WORKER, LATER)
    with pytest.raises(ValueError, match=message):
        job_writer.finish(paths, JOB_ID, state=state, error=error, result=result, now=LATER)
    assert _read(_queued(paths))["state"] == "running"


def test_finish_checks_a_result_against_its_action(paths) -> None:
    schemas = {"project.deploy": obj({"count": INTEGER})}.get
    job_writer.publish(paths, _record())
    job_writer.claim(paths, JOB_ID, WORKER, LATER)
    with pytest.raises(ValueError, match=r"\$.result.count: expected integer"):
        job_writer.finish(paths, JOB_ID, state="succeeded", error=None, result={"count": "3"},
                          now=LATER, result_schemas=schemas)
    with pytest.raises(ValueError, match="no registered result schema"):
        job_writer.finish(paths, JOB_ID, state="succeeded", error=None, result={"count": 3},
                          now=LATER, result_schemas=lambda action: None)
    done = job_writer.finish(paths, JOB_ID, state="succeeded", error=None, result={"count": 3},
                             now=LATER, result_schemas=schemas)
    assert _read(_done(paths))["result"] == {"count": 3} == done["result"]


def test_fail_unclaimed_fails_a_queued_job_and_moves_it_out(paths) -> None:
    job_writer.publish(paths, _record())
    error = {"code": "failed", "message": "its worker crashed before the claim"}
    done = job_writer.fail_unclaimed(paths, JOB_ID, error=error, now=LATER)
    assert (done["state"], done["error"], done["worker"]) == ("failed", error, None)
    assert _read(_done(paths)) == done and not _queued(paths).exists()


def test_fail_unclaimed_leaves_a_claimed_or_missing_job(paths) -> None:
    error = {"code": "failed", "message": "x"}
    assert job_writer.fail_unclaimed(paths, JOB_ID, error=error, now=LATER) is None
    job_writer.publish(paths, _record())
    job_writer.claim(paths, JOB_ID, WORKER, LATER)
    assert job_writer.fail_unclaimed(paths, JOB_ID, error=error, now=LATER) is None
    assert _read(_queued(paths))["state"] == "running"


def test_complete_finish_moves_a_terminal_record_left_in_queue(paths) -> None:
    terminal = _record(state="failed", worker=WORKER.as_record(),
                       started_at="2026-11-15T12:00:05Z", finished_at="2026-11-15T12:01:00Z",
                       error={"code": "worker_lost", "message": "gone"})
    _queued(paths).parent.mkdir(parents=True)
    _queued(paths).write_text(json.dumps(terminal))
    with _Recorder(paths) as rec:
        job_writer.complete_finish(paths, JOB_ID)
    assert rec.events == [("link", f"jobs/{NAME}"), ("fsync", "jobs/"),
                          ("unlink", f"queue/{NAME}"), ("fsync", "queue/")]
    assert _read(_done(paths)) == terminal and not _queued(paths).exists()


def _crash_after(paths, step: str) -> None:
    """Make every real durable_unlink after the first link of *step* the
    crash point: the step stops there, as a reboot would stop it."""
    class Crash(Exception):
        pass

    def crash(path):
        raise Crash(path)

    # A reboot runs no cleanup, so a publish's withdrawal never happens.
    with patch.object(job_writer, "durable_unlink", crash), \
            patch.object(job_writer, "_withdraw", lambda *args: None), pytest.raises(Crash):
        if step == "publish":
            job_writer.publish(paths, _record())
        else:
            job_writer.finish(paths, JOB_ID, state="succeeded", error=None, result=None,
                              now=LATER)


def test_reboot_after_the_publish_link_leaves_a_job_that_is_claimed(paths) -> None:
    _crash_after(paths, "publish")
    assert os.stat(_queued(paths)).st_nlink == 2
    assert job_writer.load_for_recovery(paths, JOB_ID)["state"] == "queued"
    assert not list(paths.jobs_dir.glob("*.tmp"))
    claimed = job_writer.claim(paths, JOB_ID, WORKER, LATER)
    assert claimed["state"] == "running" and os.stat(_queued(paths)).st_nlink == 1


def test_claim_itself_clears_a_crashed_publish(paths) -> None:
    _crash_after(paths, "publish")
    assert job_writer.claim(paths, JOB_ID, WORKER, LATER)["state"] == "running"
    assert not list(paths.jobs_dir.glob("*.tmp"))


def test_reboot_after_the_finish_link_recovers_as_a_finish_to_complete(paths) -> None:
    job_writer.publish(paths, _record())
    job_writer.claim(paths, JOB_ID, WORKER, LATER)
    _crash_after(paths, "finish")
    assert os.path.samefile(_queued(paths), _done(paths))
    found = job_writer.load_for_recovery(paths, JOB_ID)
    assert found["state"] == "succeeded"
    job_writer.complete_finish(paths, JOB_ID)
    assert _read(_done(paths)) == found and not _queued(paths).exists()
    assert os.stat(_done(paths)).st_nlink == 1
    assert job_writer.load_for_recovery(paths, JOB_ID) is None


def test_load_for_recovery_refuses_a_record_linked_from_elsewhere(paths, tmp_path) -> None:
    job_writer.publish(paths, _record())
    os.link(_queued(paths), tmp_path / "elsewhere.json")
    with pytest.raises(StateError, match="2 links"):
        job_writer.load_for_recovery(paths, JOB_ID)


def test_a_record_under_the_wrong_name_is_refused(paths) -> None:
    _queued(paths).parent.mkdir(parents=True)
    _queued(paths).write_text(json.dumps({**_record(), "id": "01J" + "B" * 23}))
    with pytest.raises(StateError, match="holds the id"):
        job_writer.claim(paths, JOB_ID, WORKER, LATER)


def test_complete_finish_refuses_a_different_record_already_in_jobs(paths) -> None:
    terminal = _record(state="succeeded", worker=WORKER.as_record(),
                       started_at="2026-11-15T12:00:05Z", finished_at="2026-11-15T12:01:00Z")
    _queued(paths).parent.mkdir(parents=True)
    _queued(paths).write_text(json.dumps(terminal))
    _done(paths).write_text("other")
    with pytest.raises(StateError, match="already holds a different record"):
        job_writer.complete_finish(paths, JOB_ID)
    assert _queued(paths).exists()


def test_complete_finish_refuses_an_unfinished_record(paths) -> None:
    job_writer.publish(paths, _record())
    with pytest.raises(StateError, match="queued"):
        job_writer.complete_finish(paths, JOB_ID)
    assert _queued(paths).exists() and not _done(paths).exists()


def test_a_job_id_that_is_not_a_ulid_is_refused(paths) -> None:
    with pytest.raises(ValueError, match="not a job id"):
        job_writer.claim(paths, "../../etc/passwd", WORKER, LATER)
