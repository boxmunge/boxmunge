"""A failed statistics flush: requeued unless the COMMIT outcome is unknown, then dropped (loudly)."""

import sqlite3
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import db  # noqa: E402
import prefix_store  # noqa: E402
from request_limits import CheckCounter  # noqa: E402

DAY = date(2026, 11, 11)


class FailingConnection:
    """A real connection that fails at `stage`: connect/begin/insert/commit raise
    before the statement runs; "commit_ran" runs the real COMMIT, then raises."""

    def __init__(self, conn, stage):
        self._conn, self._stage = conn, stage

    def _check(self, sql):
        if sql == "COMMIT" and self._stage == "commit_ran":
            self._conn.execute(sql)
            raise sqlite3.OperationalError("injected commit_ran failure")
        if (self._stage == "begin" and sql.startswith("BEGIN")) or \
                (self._stage == "commit" and sql == "COMMIT"):
            raise sqlite3.OperationalError(f"injected {self._stage} failure")

    def execute(self, sql, *args):
        self._check(sql)
        return self._conn.execute(sql, *args)

    def executemany(self, sql, *args):
        if self._stage == "insert":
            raise sqlite3.OperationalError("injected insert failure")
        return self._conn.executemany(sql, *args)

    def __getattr__(self, name):
        return getattr(self._conn, name)


@pytest.fixture
def fail_once(monkeypatch):
    real = db.connect

    def arm(stage):
        state = {"armed": True}

        def connect(path, **kwargs):
            if state["armed"]:
                state["armed"] = False
                if stage == "connect":
                    raise sqlite3.OperationalError("injected connect failure")
                return FailingConnection(real(path, **kwargs), stage)
            return real(path, **kwargs)
        monkeypatch.setattr(db, "connect", connect)
    return arm


def _counts(path):
    conn = sqlite3.connect(path)
    try:
        return dict(((d, v), c) for d, v, c in conn.execute("SELECT date, version, count FROM version_checks"))
    finally:
        conn.close()


def _sightings(path):
    conn = sqlite3.connect(path)
    try:
        return set(conn.execute("SELECT date, prefix, version FROM prefix_checks"))
    finally:
        conn.close()


def _counter(path, max_pending=100):
    return CheckCounter(path, flush_interval=3600, max_pending=max_pending, clock=lambda: 0.0,
                        today=lambda: DAY)


def _log(path, max_pending=100):
    return prefix_store.PrefixLog(path, 3600, max_pending, frozenset({"0.1.0", "0.2.0"}),
                                  clock=lambda: 0.0, today=lambda: DAY)


@pytest.mark.parametrize("stage", ["connect", "begin", "insert", "commit"])
class TestRequeued:
    def test_counts_are_requeued_and_merged_with_arrivals(self, migrated_db, fail_once, stage, capsys):
        counter = _counter(migrated_db)
        counter.record("0.1.0")
        counter.record("0.1.0")
        fail_once(stage)
        with pytest.raises(sqlite3.OperationalError, match=stage):
            counter.flush()
        counter.record("0.1.0")  # arrives after the failure
        counter.flush()
        assert _counts(migrated_db) == {("2026-11-11", "0.1.0"): 3}
        err = capsys.readouterr().err
        assert "ERROR check-counter" in err and "requeued a batch of 2" in err

    def test_sightings_are_requeued(self, migrated_db, fail_once, stage, capsys):
        log = _log(migrated_db)
        log.record("10.0.0.0/24", "0.1.0")
        fail_once(stage)
        with pytest.raises(sqlite3.OperationalError, match=stage):
            log.flush()
        log.record("10.0.1.0/24", "0.2.0")
        log.flush()
        assert _sightings(migrated_db) == {("2026-11-11", "10.0.0.0/24", "0.1.0"),
                                           ("2026-11-11", "10.0.1.0/24", "0.2.0")}
        assert "ERROR prefix-log" in capsys.readouterr().err


class TestCommitOutcomeUnknown:
    """COMMIT ran (or ROLLBACK failed): the batch may be written, so it is dropped."""

    def test_counts_are_dropped_not_double_counted(self, migrated_db, fail_once, capsys):
        counter = _counter(migrated_db)
        counter.record("0.1.0")
        counter.record("0.1.0")
        fail_once("commit_ran")
        with pytest.raises(sqlite3.OperationalError, match="commit_ran"):
            counter.flush()
        assert _counts(migrated_db) == {("2026-11-11", "0.1.0"): 2}  # it did commit
        counter.flush()  # nothing was requeued
        assert _counts(migrated_db) == {("2026-11-11", "0.1.0"): 2}
        counter.record("0.2.0")
        counter.flush()
        assert _counts(migrated_db)[("2026-11-11", "0.2.0")] == 1
        err = capsys.readouterr().err
        assert "ERROR check-counter" in err and "already closed, outcome unknown" in err and "batch of 2" in err

    def test_sightings_are_dropped(self, migrated_db, fail_once, capsys):
        log = _log(migrated_db)
        log.record("10.0.0.0/24", "0.1.0")
        fail_once("commit_ran")
        with pytest.raises(sqlite3.OperationalError):
            log.flush()
        log.flush()
        assert _sightings(migrated_db) == {("2026-11-11", "10.0.0.0/24", "0.1.0")}
        err = capsys.readouterr().err
        assert "ERROR prefix-log" in err and "outcome unknown" in err and "batch of 1" in err

    def test_failed_rollback_after_failed_commit_drops(self, migrated_db, monkeypatch, capsys):
        real = db.connect

        class Conn(FailingConnection):
            def execute(self, sql, *args):
                if sql == "ROLLBACK":
                    raise sqlite3.OperationalError("injected rollback failure")
                return super().execute(sql, *args)
        monkeypatch.setattr(db, "connect", lambda path, **kw: Conn(real(path, **kw), "commit"))
        counter = _counter(migrated_db)
        counter.record("0.1.0")
        with pytest.raises(sqlite3.OperationalError):
            counter.flush()
        monkeypatch.undo()
        counter.flush()
        assert _counts(migrated_db) == {}
        assert "COMMIT failed and so did ROLLBACK" in capsys.readouterr().err


class TestFullBufferWithDatabaseDown:
    def _down(self, monkeypatch):
        attempts = []

        def connect(path, **kwargs):
            attempts.append(1)
            raise sqlite3.OperationalError("database is locked")
        monkeypatch.setattr(db, "connect", connect)
        return attempts

    def test_counter_makes_no_attempts_until_the_interval(self, migrated_db, monkeypatch, capsys):
        now = [0.0]
        counter = CheckCounter(migrated_db, flush_interval=60, max_pending=2,
                               clock=lambda: now[0], today=lambda: DAY)
        counter.record("0.1.0")
        attempts = self._down(monkeypatch)
        with pytest.raises(sqlite3.OperationalError):
            counter.record("0.2.0")  # full: one attempt, fails, requeued
        assert len(attempts) == 1
        for v in ("0.1.0", "0.3.0", "0.4.0", "0.5.0"):  # nothing raises, no attempts
            counter.record(v)
        assert len(attempts) == 1
        assert len(counter._pending) == 2
        assert counter._pending[("2026-11-11", "0.1.0")] == 2  # known keys still count
        now[0] = 60
        with pytest.raises(sqlite3.OperationalError):
            counter.record("0.1.0")  # interval passed: exactly one attempt
        assert len(attempts) == 2
        err = capsys.readouterr().err
        assert "dropped 3 new entries" in err

    def test_log_makes_no_attempts_until_the_interval(self, migrated_db, monkeypatch, capsys):
        now = [0.0]
        log = prefix_store.PrefixLog(migrated_db, 60, 2, frozenset({"0.1.0"}),
                                     clock=lambda: now[0], today=lambda: DAY)
        log.record("10.0.0.0/24", "0.1.0")
        attempts = self._down(monkeypatch)
        with pytest.raises(sqlite3.OperationalError):
            log.record("10.0.1.0/24", "0.1.0")
        for i in range(2, 6):
            log.record(f"10.0.{i}.0/24", "0.1.0")
        assert len(attempts) == 1 and len(log._pending) == 2
        now[0] = 60
        with pytest.raises(sqlite3.OperationalError):
            log.record("10.0.9.0/24", "0.1.0")
        assert len(attempts) == 2
        assert "dropped 5 new entries" in capsys.readouterr().err

    def test_success_clears_the_waiting_state(self, migrated_db, fail_once):
        counter = _counter(migrated_db, max_pending=1)
        fail_once("begin")
        with pytest.raises(sqlite3.OperationalError):
            counter.record("0.1.0")
        counter.flush()  # database is back
        assert _counts(migrated_db) == {("2026-11-11", "0.1.0"): 1}
        counter.record("0.2.0")  # full again: flushes straight away, as before any failure
        assert ("2026-11-11", "0.2.0") in _counts(migrated_db)


class TestBounds:
    def test_counts_requeue_stays_within_max_pending(self, migrated_db):
        counter = _counter(migrated_db, max_pending=2)
        counter._pending.update({("2026-11-11", "0.8.0"): 1, ("2026-11-11", "0.9.0"): 1})
        lost = counter._requeue({("2026-11-11", "0.1.0"): 4, ("2026-11-11", "0.8.0"): 2})
        assert lost == 4
        assert counter._pending == {("2026-11-11", "0.8.0"): 3, ("2026-11-11", "0.9.0"): 1}

    def test_sightings_requeue_stays_within_max_pending(self, migrated_db):
        log = _log(migrated_db, max_pending=2)
        log._pending = {("2026-11-11", "a", "0.1.0")}
        lost = log._requeue({("2026-11-11", "b", "0.1.0"), ("2026-11-11", "c", "0.1.0")})
        assert lost == 1 and len(log._pending) == 2
