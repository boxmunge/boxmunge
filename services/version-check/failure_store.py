"""Upgrade-failure reports: distinct failures per reporter per window, bounded.

A reporter is prefix_store.network_prefix of the client address (the IPv4
/24 or IPv6 /48), never the address itself. One network can hold many
boxes (at some hosters one /48 spans many customers), so a reporter's
report is stored unless it repeats one the same reporter already sent for
that version in REPORT_WINDOW (same from-version, stage and detail), up to
REPORTS_PER_REPORTER per version per window. The maintainer alert
(failure_alert) counts distinct reporters in that same window, never
reports: a network counts once, however many of its boxes fail.
Reports, reporter included, are deleted after RETENTION by expire(), which
retention.sweep runs on a schedule.
"""

from datetime import datetime, timedelta
from pathlib import Path

import db

REPORT_WINDOW = timedelta(hours=6)
RETENTION = timedelta(days=90)
REPORTS_PER_REPORTER = 10

WINDOW_SQL = ("SELECT installed_from, stage, detail FROM failures WHERE reporter = ? "
              "AND version = ? AND reported_at > ?")
EXPIRE_SQL = "DELETE FROM failures WHERE reported_at <= ?"
REPORTED_BY_SQL = ("SELECT version FROM failures WHERE reported_at > ? GROUP BY version "
                   "HAVING COUNT(DISTINCT reporter) >= ?")


def record_failure(db_path: Path, version: str, installed_from: str, stage: str,
                   reporter: str, now: datetime, detail: str | None = None) -> bool:
    """Store a report; False if `reporter` already sent this one for `version`
    in the window, or REPORTS_PER_REPORTER others.

    The check and the insert share one IMMEDIATE transaction, so concurrent
    copies of one report (one per gunicorn worker) store one.
    """
    window_start = (now - REPORT_WINDOW).isoformat()
    conn = db.connect(db_path, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            sent = conn.execute(WINDOW_SQL, (reporter, version, window_start)).fetchall()
            store = ((installed_from, stage, detail) not in sent
                     and len(sent) < REPORTS_PER_REPORTER)
            if store:
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
    return store


def expire(db_path: Path, now: datetime) -> None:
    """Delete reports past retention."""
    conn = db.connect(db_path)
    try:
        conn.execute(EXPIRE_SQL, ((now - RETENTION).isoformat(),))
        conn.commit()
    finally:
        conn.close()


def versions_reported_by(db_path: Path, now: datetime, reporters: int) -> set[str]:
    """Versions with reports from at least `reporters` distinct reporters in the window."""
    conn = db.connect(db_path)
    try:
        rows = conn.execute(REPORTED_BY_SQL,
                            ((now - REPORT_WINDOW).isoformat(), reporters)).fetchall()
    finally:
        conn.close()
    return {row[0] for row in rows}


def recent_failures(db_path: Path, limit: int) -> list[dict]:
    """The newest `limit` reports, newest first, with the reporter's network prefix."""
    conn = db.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT reported_at, version, installed_from, stage, detail, reporter FROM failures "
            "ORDER BY reported_at DESC, id DESC LIMIT ?", (limit,)).fetchall()
    finally:
        conn.close()
    keys = ("reported_at", "version", "installed_from", "stage", "detail", "reporter")
    return [dict(zip(keys, row)) for row in rows]


def query_failures(db_path: Path, version: str) -> dict:
    """Reports for `version` in retention: `total` reports, from `reporters`
    distinct networks (legacy rows without a reporter are not counted there)."""
    conn = db.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT stage, COUNT(*) FROM failures WHERE version = ? GROUP BY stage",
            (version,)).fetchall()
        time_range = conn.execute(
            "SELECT MIN(reported_at), MAX(reported_at), COUNT(DISTINCT reporter) FROM failures "
            "WHERE version = ?", (version,)).fetchone()
    finally:
        conn.close()
    by_stage = {row[0]: row[1] for row in rows}
    total = sum(by_stage.values())
    return {
        "version": version,
        "total": total,
        "reporters": time_range[2],
        "by_stage": by_stage,
        "first_seen": time_range[0] if total > 0 else None,
        "last_seen": time_range[1] if total > 0 else None,
    }
