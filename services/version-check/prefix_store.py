"""Which network runs which version: IPv4 /24 or IPv6 /48 prefixes, kept 90 days.

During the early beta the users are a handful of people the maintainer knows,
so the admin stats page lists the networks that checked for updates, the
version each reported and when, to tell who to nudge off an old release.

network_prefix() is the only form of a client address this service writes
to its database (here, and as failure reporters); the full address is never
stored. A sighting is (UTC date, prefix,
version), one row per distinct triple. Rows older than RETENTION_DAYS are
purged by retention.sweep (at start and every few minutes), so the published
privacy statement (static/index.html) holds whether or not checks arrive.

PrefixLog buffers sightings in memory and writes them in one transaction,
like request_limits.CheckCounter, so an unauthenticated check never waits on
a write. Rows are bounded: unlisted versions are stored as UNLISTED, and a
day holds at most max_prefixes_per_day distinct prefixes, each with at most
max_versions_per_prefix versions.
"""

import atexit
import ipaddress
import re
import sys
import threading
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Callable

import db
from request_limits import report_failed_flush, utc_today

RETENTION_DAYS = 90
UNLISTED = "unlisted"
# A handful of beta users is a few dozen prefixes; these only bound abuse,
# so a day holds at most MAX_PREFIXES_PER_DAY * MAX_VERSIONS_PER_PREFIX_PER_DAY
# rows. Three versions covers an upgrade and a rollback on one day.
MAX_PREFIXES_PER_DAY = 5000
MAX_VERSIONS_PER_PREFIX_PER_DAY = 3
PURGE_SQL = "DELETE FROM prefix_checks WHERE date <= ?"
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)\Z")


def network_prefix(addr: str | None) -> str:
    """The IPv4 /24 or IPv6 /48 containing `addr`.

    IPv6 that embeds an IPv4 address counts as that IPv4 address: an
    IPv4-mapped address, and a 6to4 address (2002::/16), whose /48 would be
    the whole IPv4 address.

    Raises ValueError for anything that is not an IP address: behind the
    trusted proxy the client address always is one, so anything else is a
    misconfiguration to surface, not a value to store.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        raise ValueError(f"client address {addr!r} is not an IP address; the service must "
                         f"sit behind the boxmunge Caddy proxy, which sets X-Forwarded-For") from None
    if ip.version == 6:
        ip = ip.ipv4_mapped or ip.sixtofour or ip
    bits = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{bits}", strict=False))


def purge(db_path: Path, now: datetime) -> None:
    """Delete sightings RETENTION_DAYS or more days old (UTC)."""
    cutoff = (now.date() - timedelta(days=RETENTION_DAYS)).isoformat()
    conn = db.connect(db_path)
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
    conn = db.connect(db_path)
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

    `listed` versions are stored as reported, any other as UNLISTED. A new
    prefix beyond `max_prefixes_per_day` on a day, or a new version beyond
    `max_versions_per_prefix` for a prefix on a day, is dropped, and each
    flush that drops any says so on stderr.
    """

    def __init__(self, db_path: Path, flush_interval: float, max_pending: int,
                 listed: frozenset[str], max_prefixes_per_day: int = MAX_PREFIXES_PER_DAY,
                 max_versions_per_prefix: int = MAX_VERSIONS_PER_PREFIX_PER_DAY,
                 clock: Callable[[], float] = time.monotonic,
                 today: Callable[[], date] = utc_today) -> None:
        self.db_path, self.listed = db_path, listed
        self.flush_interval, self.max_pending = flush_interval, max_pending
        self.max_prefixes_per_day = max_prefixes_per_day
        self.max_versions_per_prefix = max_versions_per_prefix
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
        dropped = 0
        committing = False
        try:
            conn = db.connect(self.db_path, isolation_level=None)
            try:
                # One write transaction, so another worker's flush cannot add
                # rows between the count and the insert.
                conn.execute("BEGIN IMMEDIATE")
                known: dict[str, dict[str, set[str]]] = {}
                rows = []
                # Oldest version first (numeric order, unlisted last), so a cap
                # never drops the oldest version a network reported.
                for day, prefix, version in sorted(
                        pending, key=lambda s: (s[0], s[1], _version_order(s[2]))):
                    if day not in known:
                        known[day] = {}
                        for p, v in conn.execute(
                                "SELECT prefix, version FROM prefix_checks WHERE date = ?", (day,)):
                            known[day].setdefault(p, set()).add(v)
                    versions = known[day].get(prefix)
                    if versions is None and len(known[day]) >= self.max_prefixes_per_day:
                        dropped += 1
                        continue
                    versions = known[day].setdefault(prefix, set())
                    if version not in versions and len(versions) >= self.max_versions_per_prefix:
                        dropped += 1
                        continue
                    versions.add(version)
                    rows.append((day, prefix, version))
                conn.executemany("INSERT OR IGNORE INTO prefix_checks (date, prefix, version) "
                                 "VALUES (?, ?, ?)", rows)
                committing = True
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()
        except BaseException as error:
            lost = 0 if committing else self._requeue(pending)
            report_failed_flush("prefix-log", len(pending), committing, error, lost)
            raise
        if dropped:
            print(f"prefix-log: dropped {dropped} sighting(s) beyond the daily caps "
                  f"({self.max_prefixes_per_day} prefixes, {self.max_versions_per_prefix} "
                  f"versions per prefix)", file=sys.stderr, flush=True)

    def _requeue(self, batch: set[tuple[str, str, str]]) -> int:
        """Merge a batch that was not written back into the buffer, which
        stays within max_pending sightings: returns how many did not fit and
        were dropped."""
        with self._lock:
            room = max(self.max_pending - len(self._pending), 0)
            fresh = sorted(batch - self._pending)
            self._pending.update(fresh[:room])
        return len(fresh) - room if len(fresh) > room else 0
