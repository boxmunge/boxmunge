"""SQLite schema of the version-check service, changed only by migrations.

The database lives on a persistent volume and outlives every deploy, so the
schema is versioned with PRAGMA user_version. MIGRATIONS[n] upgrades a
database at version n to n + 1, and init_db applies the missing ones in order
at startup. Databases created before versioning report version 0 and already
hold the baseline tables, which the first migration creates only if absent.

All migrations run in one IMMEDIATE transaction: gunicorn workers starting
together apply them once, and a migration that fails leaves the database as
it was and stops the service from starting.
"""

import sqlite3
from pathlib import Path

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
    """Deduplicate by reporter (IPv4 address or IPv6 /64), with indexes."""
    conn.execute("ALTER TABLE failures RENAME COLUMN remote_addr TO reporter")
    rows = conn.execute("SELECT id, reporter FROM failures WHERE reporter IS NOT NULL").fetchall()
    conn.executemany("UPDATE failures SET reporter = ? WHERE id = ?",
                     [(client_key(addr), row_id) for row_id, addr in rows])
    conn.execute("CREATE INDEX failures_by_version ON failures (version, reported_at)")
    conn.execute("CREATE INDEX failures_by_time ON failures (reported_at)")
    conn.execute("CREATE INDEX failures_by_reporter ON failures (reporter, version, reported_at) "
                 "WHERE reporter IS NOT NULL")


MIGRATIONS = (_baseline, _reporter_identity)
SCHEMA_VERSION = len(MIGRATIONS)


def init_db(db_path: Path) -> None:
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
            for migrate in MIGRATIONS[version:]:
                migrate(conn)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
