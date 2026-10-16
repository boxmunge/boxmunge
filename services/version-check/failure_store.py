"""Upgrade-failure reports: one per reporter per version per window, bounded.

A reporter is request_limits.client_key of the client address (the IPv4
address, or the IPv6 /64), the grouping the rate limiter uses, so the many
addresses one host owns count once. A reporter counts once per version per
REPORT_WINDOW, and the auto-trip threshold counts reports in that same
window, so the threshold is a number of distinct reporters. Reporter
identities are forgotten once outside the window; reports are deleted after
RETENTION, so the table stays bounded however long the service runs.
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

REPORT_WINDOW = timedelta(hours=6)
RETENTION = timedelta(days=90)

DUPLICATE_SQL = ("SELECT 1 FROM failures WHERE reporter = ? AND version = ? "
                 "AND reported_at > ? LIMIT 1")
FORGET_SQL = "UPDATE failures SET reporter = NULL WHERE reporter IS NOT NULL AND reported_at <= ?"
EXPIRE_SQL = "DELETE FROM failures WHERE reported_at <= ?"
COUNT_SQL = "SELECT COUNT(*) FROM failures WHERE version = ? AND reported_at > ?"


def record_failure(db_path: Path, version: str, installed_from: str, stage: str,
                   reporter: str, now: datetime) -> bool:
    """Store a report; False if `reporter` already reported `version` in the window.

    The duplicate check and the insert share one IMMEDIATE transaction, so
    concurrent reports from one reporter (one per gunicorn worker) store one.
    """
    window_start = (now - REPORT_WINDOW).isoformat()
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(EXPIRE_SQL, ((now - RETENTION).isoformat(),))
            conn.execute(FORGET_SQL, (window_start,))
            duplicate = conn.execute(DUPLICATE_SQL, (reporter, version, window_start)).fetchone()
            if duplicate is None:
                conn.execute(
                    "INSERT INTO failures (version, installed_from, stage, reported_at, reporter) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (version, installed_from, stage, now.isoformat(), reporter))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return duplicate is None


def count_recent(db_path: Path, version: str, now: datetime) -> int:
    """Reports for `version` in the window: the number of distinct reporters."""
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(COUNT_SQL, (version, (now - REPORT_WINDOW).isoformat())).fetchone()[0]
    finally:
        conn.close()


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
