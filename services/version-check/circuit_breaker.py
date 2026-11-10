"""The circuit breaker: releases the maintainer holds back from every box.

Only the maintainer trips it, through the authenticated
/v1/circuit-breaker/trip endpoint. Failure reports never do: they are
unauthenticated, so they only alert (failure_alert).
"""

from datetime import datetime, timezone
from pathlib import Path

import db

TRIPPED_SQL = "SELECT version FROM circuit_breaker WHERE tripped = 1"


def is_tripped(db_path: Path, version: str) -> bool:
    conn = db.connect(db_path)
    try:
        row = conn.execute(TRIPPED_SQL + " AND version = ?", (version,)).fetchone()
    finally:
        conn.close()
    return row is not None


def tripped_versions(db_path: Path) -> set[str]:
    conn = db.connect(db_path)
    try:
        return {row[0] for row in conn.execute(TRIPPED_SQL)}
    finally:
        conn.close()


def trip(db_path: Path, version: str, tripped_by: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = db.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO circuit_breaker (version, tripped, tripped_by, tripped_at)
               VALUES (?, 1, ?, ?)
               ON CONFLICT (version) DO UPDATE SET tripped = 1, tripped_by = ?, tripped_at = ?""",
            (version, tripped_by, now, tripped_by, now))
        conn.commit()
    finally:
        conn.close()


def reset(db_path: Path, version: str) -> None:
    conn = db.connect(db_path)
    try:
        conn.execute("UPDATE circuit_breaker SET tripped = 0 WHERE version = ?", (version,))
        conn.commit()
    finally:
        conn.close()
