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

import ipaddress
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import db
import failure_store
import retention
from prefix_store import network_prefix
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
    conn.execute("UPDATE failures SET reporter = NULL WHERE reporter IS NOT NULL "
                 "AND reported_at <= ?", ((now - failure_store.REPORT_WINDOW).isoformat(),))
    conn.execute(failure_store.EXPIRE_SQL, ((now - failure_store.RETENTION).isoformat(),))
    rows = conn.execute("SELECT id, reporter FROM failures WHERE reporter IS NOT NULL").fetchall()
    conn.executemany("UPDATE failures SET reporter = ? WHERE id = ?",
                     [(client_key(addr), row_id) for row_id, addr in rows])
    conn.execute("CREATE INDEX failures_by_version ON failures (version, reported_at)")
    conn.execute("CREATE INDEX failures_by_time ON failures (reported_at)")
    conn.execute("CREATE INDEX failures_by_reporter ON failures (reporter, version, reported_at) "
                 "WHERE reporter IS NOT NULL")


def _failure_detail(conn: sqlite3.Connection) -> None:
    """The reason an upgrade failed (bounded, printable ASCII), when the box says."""
    conn.execute("ALTER TABLE failures ADD COLUMN detail TEXT")


def _admin_passkey(conn: sqlite3.Connection) -> None:
    """The admin pages' passkey, its ceremonies' challenges, and the session key.

    One credential at most (slot is always 1). code_mac is an HMAC of the
    registration code it was registered under, never the code itself.
    Challenges live here, not in memory, because each gunicorn worker serves
    a different step of the same ceremony; `client` (the requester's
    client_key, dropped by _network_prefixes) bounds how many one client can
    hold. The random session key
    never leaves the database, so STATS_SECRET alone cannot sign a session.
    """
    conn.execute("""
        CREATE TABLE admin_credential (
            slot          INTEGER PRIMARY KEY CHECK (slot = 1),
            credential_id BLOB NOT NULL,
            public_key    BLOB NOT NULL,
            sign_count    INTEGER NOT NULL,
            code_mac      TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE admin_challenges (
            challenge    BLOB PRIMARY KEY,
            purpose      TEXT NOT NULL CHECK (purpose IN ('register', 'login')),
            client       TEXT NOT NULL,
            expires_unix INTEGER NOT NULL
        )
    """)
    conn.execute("CREATE INDEX admin_challenges_by_client ON admin_challenges (client)")
    conn.execute("""
        CREATE TABLE admin_session_key (
            slot INTEGER PRIMARY KEY CHECK (slot = 1),
            key  BLOB NOT NULL
        )
    """)
    conn.execute("INSERT INTO admin_session_key (slot, key) VALUES (1, ?)",
                 (secrets.token_bytes(32),))


def _stored_prefix(key: str) -> str | None:
    """The network prefix of a stored client_key (an IPv4 address or IPv6 /64),
    or None for a key that is not one (client_key passes such values through)."""
    try:
        network = ipaddress.ip_network(key, strict=False)
    except ValueError:
        return None
    return network_prefix(str(network.network_address))


def _network_prefixes(conn: sqlite3.Connection) -> None:
    """Store client networks (IPv4 /24, IPv6 /48), never client addresses.

    prefix_checks holds one row per (UTC date, prefix, version) a check
    reported; see prefix_store. Failure reporters become prefixes, and are
    kept as long as their report; a reporter that is not an address is
    cleared, and counted on stdout. Passkey challenges no longer record their
    requester (the per-client cap moved to memory, see passkey_routes);
    pending ones, which live five minutes, are dropped: a ceremony in flight
    during the deploy starts again.

    Every connection zeroes what it frees (db.connect), but earlier releases
    deleted addresses without that, so their bytes may linger in free pages.
    pending_vacuum marks the database for one VACUUM, which prepare() runs
    and only then clears, so an interrupted start retries it.
    """
    conn.execute("""
        CREATE TABLE prefix_checks (
            date    TEXT NOT NULL,
            prefix  TEXT NOT NULL,
            version TEXT NOT NULL,
            PRIMARY KEY (prefix, date, version)
        )
    """)
    conn.execute("CREATE INDEX prefix_checks_by_date ON prefix_checks (date)")
    rows = conn.execute("SELECT id, reporter FROM failures WHERE reporter IS NOT NULL").fetchall()
    converted = [(_stored_prefix(key), row_id) for row_id, key in rows]
    conn.executemany("UPDATE failures SET reporter = ? WHERE id = ?", converted)
    cleared = sum(1 for prefix, _ in converted if prefix is None)
    if cleared:
        print(f"db_schema: cleared {cleared} failure reporter(s) that were not IP addresses",
              flush=True)
    conn.execute("DELETE FROM admin_challenges")
    conn.execute("DROP INDEX admin_challenges_by_client")
    conn.execute("ALTER TABLE admin_challenges DROP COLUMN client")
    conn.execute("CREATE TABLE pending_vacuum (slot INTEGER PRIMARY KEY CHECK (slot = 1))")
    conn.execute("INSERT INTO pending_vacuum (slot) VALUES (1)")


MIGRATIONS = (_baseline, _reporter_identity, _failure_detail, _admin_passkey,
              _network_prefixes)
SCHEMA_VERSION = len(MIGRATIONS)


def migrate(db_path: Path) -> None:
    """Create the database or bring it to SCHEMA_VERSION."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = db.connect(db_path, isolation_level=None)
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


def vacuum_if_pending(db_path: Path) -> None:
    """Run the VACUUM a migration asked for (pending_vacuum), then clear the mark."""
    conn = db.connect(db_path, isolation_level=None)
    try:
        if conn.execute("SELECT 1 FROM pending_vacuum").fetchone() is None:
            return
        conn.execute("VACUUM")
        conn.execute("DELETE FROM pending_vacuum")
    finally:
        conn.close()


def prepare(db_path: Path, now: datetime) -> None:
    """The pre-start step: migrate, then the first (possibly large) sweep.

    The sweep's expiry deletes run here, not in a worker, so a backlog of old
    rows is deleted once before any request waits on the database.
    """
    print(f"db_schema: preparing {db_path} (schema version {SCHEMA_VERSION})", flush=True)
    started = time.monotonic()
    migrate(db_path)
    retention.sweep(db_path, now)
    vacuum_if_pending(db_path)
    print(f"db_schema: {db_path} ready in {time.monotonic() - started:.1f}s", flush=True)


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
