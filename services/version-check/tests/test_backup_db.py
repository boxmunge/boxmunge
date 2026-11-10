"""The service's backup: a consistent copy of the live database, and a safe restore.

boxmunge runs manifest.yml's dump_command inside the running container and
keeps its stdout; restore_command gets that back on stdin. Copying the file
(`cat`) while a worker writes is not a backup (VC-5): in SQLite's default
rollback-journal mode, uncommitted pages can already be in the file, with the
hot journal that would undo them left behind.
"""

import io
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import backup_db
import db_schema
import failure_store

SERVICE_DIR = Path(__file__).parent.parent


def _report(db_path, reporter="198.51.100.0/24", detail=None):
    failure_store.record_failure(db_path, "0.2.1", "0.2.0", "apply", reporter,
                                 datetime.now(timezone.utc), detail)


def _reports(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT reporter, detail FROM failures ORDER BY id").fetchall()
    finally:
        conn.close()


@pytest.fixture
def writer_mid_transaction(migrated_db):
    """A worker inside a large write transaction whose pages spill into the file."""
    for n in range(300):
        _report(migrated_db, f"198.51.{n // 250}.{n % 250}/32", "x" * 150)
    conn = sqlite3.connect(migrated_db, isolation_level=None)
    conn.execute("PRAGMA cache_size = 2")
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("DELETE FROM failures WHERE id % 2 = 0")
    conn.executemany(
        "INSERT INTO failures (version, installed_from, stage, detail, reported_at, reporter) "
        "VALUES ('0.2.1', '0.2.0', 'apply', ?, '2026-01-01T00:00:00+00:00', 'uncommitted')",
        [("y" * 150,) for _ in range(500)])
    yield migrated_db
    conn.execute("ROLLBACK")
    conn.close()


def _integrity(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute("PRAGMA integrity_check").fetchall()
    finally:
        conn.close()


class TestDump:
    def test_copying_the_file_mid_transaction_is_not_a_backup(self, writer_mid_transaction):
        """Why the dump is not `cat`: the copy is torn or holds uncommitted rows."""
        copy = writer_mid_transaction.read_bytes()
        integrity = _integrity_of_bytes(copy)
        if integrity == [("ok",)]:
            conn = sqlite3.connect(":memory:")
            conn.deserialize(copy)
            assert conn.execute(
                "SELECT COUNT(*) FROM failures WHERE reporter = 'uncommitted'").fetchone()[0]
        else:
            assert integrity  # torn: SQLite reports the damage

    def test_dump_beside_a_write_transaction_is_the_committed_database(self, migrated_db,
                                                                       tmp_path):
        _report(migrated_db, detail="committed")
        writer = sqlite3.connect(migrated_db, isolation_level=None)
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("UPDATE failures SET detail = 'uncommitted'")
        try:
            out = io.BytesIO()
            backup_db.dump(migrated_db, out)
        finally:
            writer.execute("ROLLBACK")
            writer.close()
        copy = tmp_path / "dump.db"
        copy.write_bytes(out.getvalue())
        assert _integrity(copy) == [("ok",)]
        assert _reports(copy) == [("198.51.100.0/24", "committed")]

    def test_dump_fails_naming_the_lock_rather_than_copy_a_writer_s_pages(
            self, writer_mid_transaction, monkeypatch):
        monkeypatch.setattr(backup_db, "LOCK_WAIT_SECONDS", 0.2)
        with pytest.raises(backup_db.StillLocked, match="stayed locked"):
            backup_db.dump(writer_mid_transaction, io.BytesIO())

    def test_dump_leaves_no_deleted_rows_in_the_bytes(self, migrated_db):
        """Rows deleted for retention must not come back through a backup."""
        _report(migrated_db, detail="deleted-detail-" + "z" * 40)
        conn = sqlite3.connect(migrated_db)
        conn.execute("DELETE FROM failures")
        conn.commit()
        conn.close()
        out = io.BytesIO()
        backup_db.dump(migrated_db, out)
        assert b"deleted-detail-" not in out.getvalue()

    def test_dump_of_a_missing_database_fails(self, tmp_path):
        with pytest.raises(sqlite3.OperationalError):
            backup_db.dump(tmp_path / "absent.db", io.BytesIO())


class TestRestore:
    def _dump(self, db_path):
        out = io.BytesIO()
        backup_db.dump(db_path, out)
        return out.getvalue()

    def test_round_trip_into_a_database_a_worker_has_open(self, migrated_db, tmp_path):
        _report(migrated_db, detail="kept")
        snapshot = self._dump(migrated_db)
        _report(migrated_db, reporter="203.0.113.0/24", detail="after the backup")
        worker = sqlite3.connect(migrated_db)  # an open connection, as a worker holds
        backup_db.restore(migrated_db, io.BytesIO(snapshot))
        assert worker.execute("SELECT detail FROM failures").fetchall() == [("kept",)]
        worker.close()
        assert _integrity(migrated_db) == [("ok",)]

    def test_waits_for_a_writer_then_fails_leaving_the_database_as_it_was(
            self, migrated_db, monkeypatch):
        _report(migrated_db, detail="kept")
        snapshot = self._dump(migrated_db)
        _report(migrated_db, reporter="203.0.113.0/24", detail="live")
        monkeypatch.setattr(backup_db, "LOCK_WAIT_SECONDS", 0.2)
        writer = sqlite3.connect(migrated_db, isolation_level=None)
        writer.execute("BEGIN IMMEDIATE")
        try:
            with pytest.raises(backup_db.StillLocked):
                backup_db.restore(migrated_db, io.BytesIO(snapshot))
        finally:
            writer.execute("ROLLBACK")
            writer.close()
        assert len(_reports(migrated_db)) == 2

    def test_an_old_schema_snapshot_is_migrated(self, migrated_db, tmp_path):
        old = tmp_path / "old.db"
        conn = sqlite3.connect(old)
        conn.executescript("""
            CREATE TABLE version_checks (date TEXT NOT NULL, version TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (date, version));
            CREATE TABLE failures (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL,
                installed_from TEXT NOT NULL, stage TEXT NOT NULL, reported_at TEXT NOT NULL,
                remote_addr TEXT);
            CREATE TABLE circuit_breaker (version TEXT PRIMARY KEY,
                tripped INTEGER NOT NULL DEFAULT 1, tripped_by TEXT, tripped_at TEXT);
        """)
        conn.close()
        backup_db.restore(migrated_db, io.BytesIO(old.read_bytes()))
        db_schema.require_current(migrated_db)

    @pytest.mark.parametrize("snapshot, match", [
        (b"", "empty"),
        (b"not a database at all", "not a readable SQLite database"),
    ])
    def test_refuses_what_is_not_a_snapshot(self, migrated_db, snapshot, match):
        _report(migrated_db, detail="live")
        with pytest.raises(backup_db.RestoreError, match=match):
            backup_db.restore(migrated_db, io.BytesIO(snapshot))
        assert _reports(migrated_db) == [("198.51.100.0/24", "live")]

    def test_refuses_another_programs_database(self, migrated_db, tmp_path):
        other = tmp_path / "other.db"
        conn = sqlite3.connect(other)
        conn.execute("CREATE TABLE something (x)")
        conn.close()
        with pytest.raises(backup_db.RestoreError, match="no failures table"):
            backup_db.restore(migrated_db, io.BytesIO(other.read_bytes()))

    def test_refuses_a_newer_schema_without_touching_the_database(self, migrated_db, tmp_path):
        _report(migrated_db, detail="live")
        newer = tmp_path / "newer.db"
        newer.write_bytes(self._dump(migrated_db))
        conn = sqlite3.connect(newer)
        conn.execute(f"PRAGMA user_version = {db_schema.SCHEMA_VERSION + 1}")
        conn.close()
        with pytest.raises(backup_db.RestoreError, match="newer"):
            backup_db.restore(migrated_db, io.BytesIO(newer.read_bytes()))
        assert _reports(migrated_db) == [("198.51.100.0/24", "live")]

    def test_refuses_a_torn_copy(self, writer_mid_transaction, migrated_db):
        torn = writer_mid_transaction.read_bytes()
        if _integrity_of_bytes(torn) == [("ok",)]:
            pytest.skip("this SQLite build did not spill uncommitted pages")
        with pytest.raises(backup_db.RestoreError, match="not a readable SQLite database|integrity"):
            backup_db.restore(migrated_db, io.BytesIO(torn))


def _integrity_of_bytes(data):
    conn = sqlite3.connect(":memory:")
    try:
        conn.deserialize(data)
        return conn.execute("PRAGMA integrity_check").fetchall()
    except sqlite3.DatabaseError as e:
        return [(str(e),)]
    finally:
        conn.close()


class TestManifest:
    def test_backup_commands_use_the_backup_module(self):
        lines = [line.strip() for line in (SERVICE_DIR / "manifest.yml").read_text().splitlines()]
        assert 'dump_command: "python backup_db.py dump /data/checks.db"' in lines
        assert 'restore_command: "python backup_db.py restore /data/checks.db"' in lines

    def test_command_line_round_trip(self, migrated_db, tmp_path):
        _report(migrated_db, detail="via the command line")
        script = str(SERVICE_DIR / "backup_db.py")
        dumped = subprocess.run([sys.executable, script, "dump", str(migrated_db)],
                                capture_output=True, check=True).stdout
        target = tmp_path / "restored.db"
        db_schema.migrate(target)
        subprocess.run([sys.executable, script, "restore", str(target)], input=dumped,
                       capture_output=True, check=True)
        assert _reports(target) == [("198.51.100.0/24", "via the command line")]

    def test_command_line_refusal_exits_non_zero_with_the_reason(self, migrated_db):
        result = subprocess.run(
            [sys.executable, str(SERVICE_DIR / "backup_db.py"), "restore", str(migrated_db)],
            input=b"", capture_output=True)
        assert result.returncode != 0
        assert b"empty" in result.stderr
