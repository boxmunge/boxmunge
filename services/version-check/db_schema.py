"""SQLite schema of the version-check service, changed only by migrations.

The database lives on a persistent volume and outlives every deploy, so the
schema is versioned with PRAGMA user_version. MIGRATIONS[n] upgrades a
database at version n to n + 1. Databases created before versioning report
version 0 and already hold the baseline tables, which the first migration
creates only if absent.

Migrations run once, before gunicorn starts (`python db_schema.py <db>`, the
image's CMD), in one IMMEDIATE transaction: a migration that fails leaves the
database as it was and the service does not start. Workers only check the
version (require_current), so a slow migration of a large table can never
be cut short by a worker's busy or boot timeout.
"""

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import failure_store
from request_limits import client_key


class SchemaError(RuntimeError):
    """The database cannot be used by this version of the service."""


def _baseline(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS version_checks (
            date    TEXT NOT NULL,
            version TEXT NOT NULL,
            count   INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (date, version)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS failures (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            version        TEXT NOT NULL,
            installed_from TEXT NOT NULL,
            stage          TEXT NOT NULL,
            reported_at    TEXT NOT NULL,
            remote_addr    TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS circuit_breaker (
            version    TEXT PRIMARY KEY,
            tripped    INTEGER NOT NULL DEFAULT 1,
            tripped_by TEXT,
            tripped_at TEXT NOT NULL
        )
    """)


def _reporter_identity(conn: sqlite3.Connection) -> None:
    """Deduplicate by reporter (IPv4 address or IPv6 /64), with indexes.

    Retention is applied before anything else: only addresses still inside
    the report window need normalising (client_key is slow per row), and
    deleting before the indexes exist keeps a large table's first sweep cheap.
    """
    conn.execute("ALTER TABLE failures RENAME COLUMN remote_addr TO reporter")
    now = datetime.now(timezone.utc)
    conn.execute(failure_store.FORGET_SQL, ((now - failure_store.REPORT_WINDOW).isoformat(),))
    conn.execute(failure_store.EXPIRE_SQL, ((now - failure_store.RETENTION).isoformat(),))
    rows = conn.execute("SELECT id, reporter FROM failures WHERE reporter IS NOT NULL").fetchall()
    conn.executemany("UPDATE failures SET reporter = ? WHERE id = ?",
                     [(client_key(addr), row_id) for row_id, addr in rows])
    conn.execute("CREATE INDEX failures_by_version ON failures (version, reported_at)")
    conn.execute("CREATE INDEX failures_by_time ON failures (reported_at)")
    conn.execute("CREATE INDEX failures_by_reporter ON failures (reporter, version, reported_at) "
                 "WHERE reporter IS NOT NULL")


MIGRATIONS = (_baseline, _reporter_identity)
SCHEMA_VERSION = len(MIGRATIONS)


def migrate(db_path: Path) -> None:
    """Create the database or bring it to SCHEMA_VERSION."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise SchemaError(
                    f"{db_path} has schema version {version}, newer than this service's "
                    f"{SCHEMA_VERSION}; deploy the service version that created it, or "
                    f"restore a backup taken before the upgrade")
            for step in MIGRATIONS[version:]:
                step(conn)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def prepare(db_path: Path, now: datetime) -> None:
    """The pre-start step: migrate, then the first (possibly large) sweep.

    The sweep's expiry delete runs here, not in a worker, so a backlog of old
    reports is deleted once before any request waits on the database.
    """
    migrate(db_path)
    failure_store.sweep(db_path, now)


def require_current(db_path: Path) -> None:
    """Refuse to serve unless the pre-start step brought the database current."""
    if not db_path.exists():
        raise SchemaError(f"{db_path} does not exist; run `python db_schema.py {db_path}` "
                          f"before starting the workers (the image's CMD does)")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()
    if version != SCHEMA_VERSION:
        raise SchemaError(
            f"{db_path} has schema version {version}, this service needs {SCHEMA_VERSION}; "
            f"run `python db_schema.py {db_path}` before starting the workers "
            f"(the image's CMD does)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python db_schema.py <database path>")
    prepare(Path(sys.argv[1]), datetime.now(timezone.utc))
