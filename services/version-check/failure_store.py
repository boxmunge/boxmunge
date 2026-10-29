"""Upgrade-failure reports: one per reporter per version per window, bounded.

A reporter is request_limits.client_key of the client address (the IPv4
address, or the IPv6 /64), the grouping the rate limiter uses, so the many
addresses one host owns count once. A reporter counts once per version per
REPORT_WINDOW, and the auto-trip threshold counts reports in that same
window, so the threshold is a number of distinct reporters. Reporter
identities are forgotten once outside the window; reports are deleted after
RETENTION. Both happen in sweep(): once before the service starts, then
every SWEEP_INTERVAL in each worker, so neither depends on reports arriving
and the published privacy statement (static/index.html) holds.
"""

import sqlite3
import sys
import threading
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

REPORT_WINDOW = timedelta(hours=6)
RETENTION = timedelta(days=90)
SWEEP_INTERVAL = timedelta(minutes=5)

DUPLICATE_SQL = ("SELECT 1 FROM failures WHERE reporter = ? AND version = ? "
                 "AND reported_at > ? LIMIT 1")
FORGET_SQL = "UPDATE failures SET reporter = NULL WHERE reporter IS NOT NULL AND reported_at <= ?"
EXPIRE_SQL = "DELETE FROM failures WHERE reported_at <= ?"
COUNT_SQL = "SELECT COUNT(*) FROM failures WHERE version = ? AND reported_at > ?"


def record_failure(db_path: Path, version: str, installed_from: str, stage: str,
                   reporter: str, now: datetime, detail: str | None = None) -> bool:
    """Store a report; False if `reporter` already reported `version` in the window.

    The DUPLICATE_SQL time bound makes this correct between sweeps.

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


def sweep(db_path: Path, now: datetime) -> None:
    """Forget reporters outside the window and delete reports past retention."""
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(FORGET_SQL, ((now - REPORT_WINDOW).isoformat(),))
            conn.execute(EXPIRE_SQL, ((now - RETENTION).isoformat(),))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


class Sweeper:
    """Runs sweep() every `interval` on a daemon thread, one per worker.

    A failed sweep is logged with its traceback and retried on the next tick;
    stopping the sweeper would quietly break the retention promise.
    """

    def __init__(self, db_path: Path, interval: timedelta,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.db_path, self.interval, self._now = db_path, interval, now
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="failure-sweeper", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()

    def _run(self) -> None:
        while not self._stop.wait(self.interval.total_seconds()):
            try:
                sweep(self.db_path, self._now())
            except Exception:
                print(f"failure-sweeper: sweep of {self.db_path} failed; retrying in "
                      f"{self.interval}", file=sys.stderr, flush=True)
                traceback.print_exc()


def count_recent(db_path: Path, version: str, now: datetime) -> int:
    """Reports for `version` in the window: the number of distinct reporters."""
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(COUNT_SQL, (version, (now - REPORT_WINDOW).isoformat())).fetchone()[0]
    finally:
        conn.close()


def recent_failures(db_path: Path, limit: int) -> list[dict]:
    """The newest `limit` reports, newest first (reporter identities are never exposed)."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT reported_at, version, installed_from, stage, detail FROM failures "
            "ORDER BY reported_at DESC, id DESC LIMIT ?", (limit,)).fetchall()
    finally:
        conn.close()
    keys = ("reported_at", "version", "installed_from", "stage", "detail")
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
