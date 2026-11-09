"""Upgrade-failure reports: one per reporter per version per window, bounded.

A reporter is prefix_store.network_prefix of the client address (the IPv4
/24 or IPv6 /48), never the address itself. A reporter counts once per
version per REPORT_WINDOW, and the auto-trip threshold counts reports in that
same window, so the threshold is a number of distinct reporting networks.
Reports, reporter included, are deleted after RETENTION by expire(), which
retention.sweep runs on a schedule.
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

REPORT_WINDOW = timedelta(hours=6)
RETENTION = timedelta(days=90)

DUPLICATE_SQL = ("SELECT 1 FROM failures WHERE reporter = ? AND version = ? "
                 "AND reported_at > ? LIMIT 1")
EXPIRE_SQL = "DELETE FROM failures WHERE reported_at <= ?"
COUNT_SQL = "SELECT COUNT(*) FROM failures WHERE version = ? AND reported_at > ?"


def record_failure(db_path: Path, version: str, installed_from: str, stage: str,
                   reporter: str, now: datetime, detail: str | None = None) -> bool:
    """Store a report; False if `reporter` already reported `version` in the window.

    The duplicate check and the insert share one IMMEDIATE transaction, so
    concurrent reports from one reporter (one per gunicorn worker) store one.
    """
    window_start = (now - REPORT_WINDOW).isoformat()
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            duplicate = conn.execute(DUPLICATE_SQL, (reporter, version, window_start)).fetchone()
            if duplicate is None:
                conn.execute(
                    "INSERT INTO failures (version, installed_from, stage, detail, reported_at, "
                    "reporter) VALUES (?, ?, ?, ?, ?, ?)",
                    (version, installed_from, stage, detail, now.isoformat(), reporter))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return duplicate is None


def expire(db_path: Path, now: datetime) -> None:
    """Delete reports past retention."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(EXPIRE_SQL, ((now - RETENTION).isoformat(),))
        conn.commit()
    finally:
        conn.close()


def count_recent(db_path: Path, version: str, now: datetime) -> int:
    """Reports for `version` in the window: the number of distinct reporters."""
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(COUNT_SQL, (version, (now - REPORT_WINDOW).isoformat())).fetchone()[0]
    finally:
        conn.close()


def recent_failures(db_path: Path, limit: int) -> list[dict]:
    """The newest `limit` reports, newest first, with the reporter's network prefix."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT reported_at, version, installed_from, stage, detail, reporter FROM failures "
            "ORDER BY reported_at DESC, id DESC LIMIT ?", (limit,)).fetchall()
    finally:
        conn.close()
    keys = ("reported_at", "version", "installed_from", "stage", "detail", "reporter")
    return [dict(zip(keys, row)) for row in rows]


def query_failures(db_path: Path, version: str) -> dict:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT stage, COUNT(*) FROM failures WHERE version = ? GROUP BY stage",
            (version,)).fetchall()
        time_range = conn.execute(
            "SELECT MIN(reported_at), MAX(reported_at) FROM failures WHERE version = ?",
            (version,)).fetchone()
    finally:
        conn.close()
    by_stage = {row[0]: row[1] for row in rows}
    total = sum(by_stage.values())
    return {
        "version": version,
        "total": total,
        "by_stage": by_stage,
        "first_seen": time_range[0] if total > 0 else None,
        "last_seen": time_range[1] if total > 0 else None,
    }
