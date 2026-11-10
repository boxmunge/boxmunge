"""Back up the service database while it runs, and restore it while it does not.

manifest.yml's backup commands, which boxmunge runs inside the container:

  python backup_db.py dump <db>     the database, consistent, on stdout
  python backup_db.py restore <db>  a dump from stdin, into the database

Copying the file is not a backup: a worker's write transaction can have
uncommitted pages in it already, and the journal that would undo them is a
separate file. dump() reads through SQLite's backup API, which copies only
committed state, into memory, and VACUUMs that copy so the bytes carry no
freed pages (rows deleted for retention stay deleted). restore() checks the
dump (a SQLite database that passes its integrity check, holding this
service's tables at a schema version this service knows) before writing
anything, then writes it through the backup API, under SQLite's locks.
Last it runs the pre-start step on it (db_schema.prepare): an older dump is
migrated, and rows past retention are deleted.

dump() is safe beside running workers: it waits for a write transaction to
end. restore() is not for a database in use: any connection inside a
transaction, a reader included, holds a lock it needs, so it waits
LOCK_WAIT_SECONDS and then fails (StillLocked), and a worker's in-memory
state would outlive the swap anyway. Run it with the project stopped, as
`boxmunge restore` does: it stops the project, starts only the backup
service for the restore, then recreates every service on the restored data.

Snapshots taken with the old `cat` dump are SQLite files too, and restore
the same way.
"""

import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

import db
import db_schema

REQUIRED_TABLE = "failures"
# How long a copy waits for a worker's write transaction (normally
# milliseconds) before it fails, naming the lock, instead of waiting for ever.
LOCK_WAIT_SECONDS = 30.0
_BUSY = (5, 6)  # SQLITE_BUSY, SQLITE_LOCKED


class RestoreError(RuntimeError):
    """The input is not a dump this service can restore; nothing was written."""


class StillLocked(RuntimeError):
    """The database stayed locked by another connection for LOCK_WAIT_SECONDS."""


def _copy(source: sqlite3.Connection, target: sqlite3.Connection, what: str,
          remedy: str) -> None:
    """The whole of `source` into `target` in one backup step, waiting at most
    LOCK_WAIT_SECONDS for the lock. (sqlite3's backup() would retry for ever.)"""
    deadline = time.monotonic() + LOCK_WAIT_SECONDS

    def progress(status: int, remaining: int, total: int) -> None:
        if status in _BUSY and time.monotonic() > deadline:
            raise StillLocked(f"{what} stayed locked by another connection for "
                              f"{LOCK_WAIT_SECONDS:g}s; {remedy}")

    source.backup(target, pages=-1, progress=progress)


def dump(db_path: Path, out: BinaryIO) -> None:
    """Write a consistent, vacuumed copy of `db_path` to `out`."""
    # timeout=0: _copy does the waiting, so it can give up.
    source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=0)
    copy = sqlite3.connect(":memory:")
    try:
        _copy(source, copy, str(db_path), "try again")
        copy.execute("VACUUM")
        out.write(copy.serialize())
    finally:
        copy.close()
        source.close()


def _checked(data: bytes) -> sqlite3.Connection:
    """`data` opened in memory, refused unless it is a dump of this service."""
    if not data:
        raise RestoreError("the dump is empty; restore a snapshot taken by `backup`")
    copy = sqlite3.connect(":memory:")
    try:
        try:
            copy.deserialize(data)
            integrity = copy.execute("PRAGMA integrity_check").fetchall()
        except sqlite3.DatabaseError as e:
            raise RestoreError(f"the dump is not a readable SQLite database ({e}); "
                               "restore an earlier snapshot") from e
        if integrity != [("ok",)]:
            raise RestoreError(f"the dump fails SQLite's integrity check ({integrity[:3]}); "
                               "restore an earlier snapshot")
        version = copy.execute("PRAGMA user_version").fetchone()[0]
        if version > db_schema.SCHEMA_VERSION:
            raise RestoreError(
                f"the dump has schema version {version}, newer than this service's "
                f"{db_schema.SCHEMA_VERSION}; deploy the service version that took it first")
        if copy.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                        (REQUIRED_TABLE,)).fetchone() is None:
            raise RestoreError(f"the dump has no {REQUIRED_TABLE} table, so it is not this "
                               "service's database")
    except BaseException:
        copy.close()
        raise
    return copy


def restore(db_path: Path, source: BinaryIO) -> None:
    """Replace the database at `db_path` with the dump read from `source`.
    The service must be stopped (see the module docstring)."""
    copy = _checked(source.read())
    try:
        live = db.connect(db_path, timeout=0)  # _copy does the waiting
        try:
            _copy(copy, live, str(db_path),
                  "stop the service (`boxmunge restore` does) and try again")
        finally:
            live.close()
    finally:
        copy.close()
    db_schema.prepare(db_path, datetime.now(timezone.utc))


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in ("dump", "restore"):
        print("usage: python backup_db.py dump|restore <database path>", file=sys.stderr)
        return 2
    command, db_path = argv[0], Path(argv[1])
    try:
        if command == "dump":
            dump(db_path, sys.stdout.buffer)
        else:
            restore(db_path, sys.stdin.buffer)
    except (RestoreError, StillLocked, sqlite3.Error, db_schema.SchemaError) as e:
        print(f"backup_db: {command} failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
