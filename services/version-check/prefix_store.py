"""Which network runs which version: IPv4 /24 or IPv6 /48 prefixes, kept 90 days.

During the early beta the users are a handful of people the maintainer knows,
so the admin stats page lists the networks that checked for updates, the
version each reported and when, to tell who to nudge off an old release.

network_prefix() is the only form of a client address this service writes
to its database (here, as failure reporters and as passkey-challenge
owners); the full address is never stored. A sighting is (UTC date, prefix,
version), one row per distinct triple. Rows older than RETENTION_DAYS are
purged by retention.sweep (at start and every few minutes), so the published
privacy statement (static/index.html) holds whether or not checks arrive.

PrefixLog buffers sightings in memory and writes them in one transaction,
like request_limits.CheckCounter, so an unauthenticated check never waits on
a write. Rows are bounded: unlisted versions are stored as UNLISTED, and a
day holds at most max_prefixes_per_day distinct prefixes.
"""

import atexit
import ipaddress
import re
import sqlite3
import sys
import threading
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Callable

from request_limits import utc_today

RETENTION_DAYS = 90
UNLISTED = "unlisted"
# A handful of beta users is a few dozen prefixes; this only bounds abuse.
MAX_PREFIXES_PER_DAY = 5000
PURGE_SQL = "DELETE FROM prefix_checks WHERE date <= ?"
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)\Z")


def network_prefix(addr: str | None) -> str:
    """The IPv4 /24 or IPv6 /48 containing `addr` (IPv4-mapped IPv6 counts as IPv4).

    Raises ValueError for anything that is not an IP address: behind the
    trusted proxy the client address always is one, so anything else is a
    misconfiguration to surface, not a value to store.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        raise ValueError(f"client address {addr!r} is not an IP address; the service must "
                         f"sit behind the boxmunge Caddy proxy, which sets X-Forwarded-For") from None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    bits = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{bits}", strict=False))


def purge(db_path: Path, now: datetime) -> None:
    """Delete sightings RETENTION_DAYS or more days old (UTC)."""
    cutoff = (now.date() - timedelta(days=RETENTION_DAYS)).isoformat()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(PURGE_SQL, (cutoff,))
        conn.commit()
    finally:
        conn.close()


def _version_order(version: str) -> tuple:
    match = _VERSION.match(version)
    return (0, *map(int, match.groups())) if match else (1, version)


def by_prefix(db_path: Path, limit: int) -> tuple[list[dict], int]:
    """The `limit` most recently seen prefixes, and how many prefixes there are.

    Each entry: prefix, first_seen, last_seen (UTC dates) and versions, every
    version seen on last_seen (two on the day a box upgraded), oldest first.
    """
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "WITH seen AS (SELECT prefix, MIN(date) AS first_seen, MAX(date) AS last_seen "
            "FROM prefix_checks GROUP BY prefix ORDER BY last_seen DESC, prefix LIMIT ?) "
            "SELECT seen.prefix, first_seen, last_seen, version FROM seen "
            "JOIN prefix_checks AS p ON p.prefix = seen.prefix AND p.date = seen.last_seen "
            "ORDER BY last_seen DESC, seen.prefix", (limit,)).fetchall()
        total = conn.execute("SELECT COUNT(DISTINCT prefix) FROM prefix_checks").fetchone()[0]
    finally:
        conn.close()
    entries: dict[str, dict] = {}
    for prefix, first_seen, last_seen, version in rows:
        entry = entries.setdefault(prefix, {"prefix": prefix, "first_seen": first_seen,
                                            "last_seen": last_seen, "versions": []})
        entry["versions"].append(version)
    for entry in entries.values():
        entry["versions"].sort(key=_version_order)
    return list(entries.values()), total


class PrefixLog:
    """Sightings buffered in memory; written every `flush_interval` seconds,
    when `max_pending` are buffered, before the admin page reads, and at exit.

    `listed` versions are stored as reported, any other as UNLISTED. New
    prefixes beyond `max_prefixes_per_day` on a day are dropped, and each
    flush that drops any says so on stderr.
    """

    def __init__(self, db_path: Path, flush_interval: float, max_pending: int,
                 listed: frozenset[str], max_prefixes_per_day: int = MAX_PREFIXES_PER_DAY,
                 clock: Callable[[], float] = time.monotonic,
                 today: Callable[[], date] = utc_today) -> None:
        self.db_path, self.listed = db_path, listed
        self.flush_interval, self.max_pending = flush_interval, max_pending
        self.max_prefixes_per_day = max_prefixes_per_day
        self._clock, self._today = clock, today
        self._lock = threading.Lock()
        self._pending: set[tuple[str, str, str]] = set()
        self._last_flush = clock()
        atexit.register(self.flush)

    def record(self, prefix: str, version: str) -> None:
        stored = version if version in self.listed else UNLISTED
        with self._lock:
            self._pending.add((self._today().isoformat(), prefix, stored))
            due = (len(self._pending) >= self.max_pending
                   or self._clock() - self._last_flush >= self.flush_interval)
        if due:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, set()
            self._last_flush = self._clock()
        if not pending:
            return
        dropped: set[tuple[str, str]] = set()
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        try:
            # One write transaction, so another worker's flush cannot add
            # prefixes between the count and the insert.
            conn.execute("BEGIN IMMEDIATE")
            known: dict[str, set[str]] = {}
            rows = []
            for day, prefix, version in sorted(pending):
                if day not in known:
                    known[day] = {r[0] for r in conn.execute(
                        "SELECT DISTINCT prefix FROM prefix_checks WHERE date = ?", (day,))}
                if prefix not in known[day] and len(known[day]) >= self.max_prefixes_per_day:
                    dropped.add((day, prefix))
                    continue
                known[day].add(prefix)
                rows.append((day, prefix, version))
            conn.executemany("INSERT OR IGNORE INTO prefix_checks (date, prefix, version) "
                             "VALUES (?, ?, ?)", rows)
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        if dropped:
            print(f"prefix-log: dropped {len(dropped)} new network prefixes beyond the cap of "
                  f"{self.max_prefixes_per_day} per day", file=sys.stderr, flush=True)
