"""Abuse limits for the public version-check service.

- client_key: the rate-limit key for a client address (IPv6 by /64, since one
  host commonly owns a whole /64).
- RateLimiter: fixed-window per-client request limit with bounded memory.
- RequestLimiter: a per-client limit, then per network once the client
  table is full (the service-wide request limit and STATS_SECRET guesses).
- CheckCounter: aggregates /v1/check counts in memory and flushes them to
  SQLite periodically, so an unauthenticated request never waits on a write.

Both are per-process (gunicorn runs several workers); limits are therefore
per worker, and each worker flushes its own counts. Counts recorded since a
worker's last flush are lost if it is killed without a clean exit.
"""

import atexit
import ipaddress
import sys
import threading
import time
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable

import db


# Why RateLimiter.admit refused a request.
LIMITED = "limited"
NETWORK_LIMITED = "network_limited"  # RequestLimiter: the client's network used its limit
FULL = "full"


def utc_today() -> date:
    """The day a check is counted under: UTC, like every other timestamp here."""
    return datetime.now(timezone.utc).date()


def client_key(remote_addr: str | None) -> str:
    """Rate-limit key for an address: the IPv4 address, or the IPv6 /64."""
    if not remote_addr:
        return "unknown"
    try:
        addr = ipaddress.ip_address(remote_addr)
    except ValueError:
        return remote_addr
    if addr.version == 4:
        return str(addr)
    if addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(ipaddress.ip_network(f"{addr}/64", strict=False))


class RateLimiter:
    """At most `limit` requests per client per `window` seconds.

    Memory is bounded: expired windows are swept once per window, and when
    `max_clients` are already tracked a new client is refused (fail closed)
    until the sweep frees room. admit() says which of the two refused.
    """

    def __init__(self, limit: int, window: float, max_clients: int,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if limit < 1 or window <= 0 or max_clients < 1:
            raise ValueError("limit, window and max_clients must be positive")
        self.limit, self.window, self.max_clients = limit, window, max_clients
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[float, int]] = {}
        self._last_sweep = clock()

    def _sweep(self, now: float) -> None:
        """Drop expired windows, at most once per window. Call with the lock held."""
        if now - self._last_sweep >= self.window:
            self._windows = {k: v for k, v in self._windows.items()
                             if now - v[0] < self.window}
            self._last_sweep = now

    def _no_room(self, key: str) -> bool:
        """True if `key` is not tracked and the table is full. Call with the lock held."""
        return key not in self._windows and len(self._windows) >= self.max_clients

    def admit(self, key: str) -> str | None:
        """Count one request for `key`: None if allowed, else why not.

        LIMITED: `key` used its whole limit in this window. FULL: `key` is not
        tracked and `max_clients` others are.
        """
        now = self._clock()
        with self._lock:
            self._sweep(now)
            started, count = self._windows.get(key, (now, 0))
            if now - started >= self.window:
                started, count = now, 0
            if self._no_room(key):
                return FULL
            if count >= self.limit:
                return LIMITED
            self._windows[key] = (started, count + 1)
            return None

    def allow(self, key: str) -> bool:
        return self.admit(key) is None

    def exhausted(self, key: str) -> bool:
        """True if `key` has used its whole limit in the current window; counts nothing."""
        now = self._clock()
        with self._lock:
            started, count = self._windows.get(key, (now, 0))
            return now - started < self.window and count >= self.limit

    def full_for(self, key: str) -> bool:
        """True if admit(key) would refuse `key` because the table is full; counts nothing."""
        with self._lock:
            self._sweep(self._clock())
            return self._no_room(key)


class RequestLimiter:
    """A per-client limit, overflowing to per network.

    Each client (client_key: an IPv4 address or IPv6 /64) gets `per_client`
    requests per window. The client table is bounded, and one IPv6 /48 alone
    holds 65,536 /64s, so one network could fill it and, were a full table
    the end of it, shut out every client not yet seen in this window: for
    the service-wide limit, every box's check would get 429 and no update
    would be installed until the flood stopped; for STATS_SECRET guesses,
    the maintainer could not sign in. So a client the full table cannot
    track is limited by its network instead (`network_of`: the /24 or /48),
    in a second bounded table, `per_network` per window. A flood from a few
    networks then exhausts only those networks; refusing a client on any
    other network takes `max_clients` distinct networks in one window.
    Like every limit here, it is per worker.
    """

    def __init__(self, per_client: int, per_network: int, window: float, max_clients: int,
                 network_of: Callable[[str | None], str],
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._clients = RateLimiter(per_client, window, max_clients, clock)
        self._networks = RateLimiter(per_network, window, max_clients, clock)
        self._network_of = network_of

    def admit(self, remote_addr: str | None) -> str | None:
        """Count one request: None if allowed, else LIMITED (the client's own
        limit), NETWORK_LIMITED (its network's, the client table being full)
        or FULL (both tables full)."""
        refused = self._clients.admit(client_key(remote_addr))
        if refused != FULL:
            return refused
        refused = self._networks.admit(self._network_of(remote_addr))
        return NETWORK_LIMITED if refused == LIMITED else refused

    def allow(self, remote_addr: str | None) -> bool:
        return self.admit(remote_addr) is None

    def refusal(self, remote_addr: str | None) -> str | None:
        """What admit() would answer now, counting nothing."""
        key = client_key(remote_addr)
        if self._clients.exhausted(key):
            return LIMITED
        if not self._clients.full_for(key):
            return None
        network = self._network_of(remote_addr)
        if self._networks.exhausted(network):
            return NETWORK_LIMITED
        return FULL if self._networks.full_for(network) else None


def report_failed_flush(buffer: str, size: int, commit_failed: bool, error: BaseException,
                        lost: int = 0) -> None:
    """Say on stderr what became of a batch whose flush failed.

    Before COMMIT nothing was written, so the batch is requeued (`lost` of it
    did not fit the buffer's bound and was dropped). A failed COMMIT may or
    may not have been applied, so the batch is dropped: requeueing it could
    count it twice, and these are statistics.
    """
    if commit_failed:
        what = (f"COMMIT failed, outcome unknown: dropped a batch of {size} "
                f"(not requeued, a retry could double-count)")
    else:
        what = f"flush failed before commit: requeued a batch of {size}"
        if lost:
            what += f", of which {lost} did not fit the buffer bound and were dropped"
    print(f"ERROR {buffer}: {what}: {error!r}", file=sys.stderr, flush=True)


OVERFLOW_VERSION = "unlisted"


class CheckCounter:
    """Daily per-version check counts, buffered in memory.

    record() never touches the database unless the buffer is due: every
    `flush_interval` seconds, or immediately when `max_pending` distinct
    (date, version) keys are buffered. flush() runs at process exit too.

    A day holds at most `max_versions_per_day` distinct versions; counts for
    further ones go to OVERFLOW_VERSION, so a client cycling through valid
    version strings cannot grow the table without bound. `always_count`
    (the listed releases) is exempt from the cap, but still counts against it,
    as does the "unlisted" overflow row itself.
    """

    def __init__(self, db_path: Path, flush_interval: float, max_pending: int,
                 max_versions_per_day: int = 200,
                 always_count: frozenset[str] = frozenset(),
                 clock: Callable[[], float] = time.monotonic,
                 today: Callable[[], date] = utc_today) -> None:
        self.db_path = db_path
        self.max_versions_per_day, self.always_count = max_versions_per_day, always_count
        self.flush_interval, self.max_pending = flush_interval, max_pending
        self._clock, self._today = clock, today
        self._lock = threading.Lock()
        self._pending: Counter[tuple[str, str]] = Counter()
        self._last_flush = clock()
        atexit.register(self.flush)

    def record(self, version: str) -> None:
        with self._lock:
            self._pending[(self._today().isoformat(), version)] += 1
            due = (len(self._pending) >= self.max_pending
                   or self._clock() - self._last_flush >= self.flush_interval)
        if due:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, Counter()
            self._last_flush = self._clock()
        if not pending:
            return
        committing = False
        try:
            conn = db.connect(self.db_path, isolation_level=None)
            try:
                # One write transaction across the select and the insert, so
                # another worker's flush cannot add versions between them.
                conn.execute("BEGIN IMMEDIATE")
                known: dict[str, set[str]] = {}
                merged: Counter[tuple[str, str]] = Counter()
                for (d, v), n in sorted(pending.items()):
                    if d not in known:
                        known[d] = {r[0] for r in conn.execute(
                            "SELECT version FROM version_checks WHERE date = ?", (d,))}
                    if (v not in known[d] and v not in self.always_count
                            and len(known[d]) >= self.max_versions_per_day):
                        v = OVERFLOW_VERSION
                    known[d].add(v)
                    merged[(d, v)] += n
                conn.executemany(
                    """INSERT INTO version_checks (date, version, count)
                       VALUES (?, ?, ?)
                       ON CONFLICT (date, version) DO UPDATE SET count = count + excluded.count""",
                    [(d, v, n) for (d, v), n in merged.items()],
                )
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
            report_failed_flush("check-counter", sum(pending.values()), committing, error, lost)
            raise

    def _requeue(self, batch: Counter[tuple[str, str]]) -> int:
        """Merge a batch that was not written back into the buffer, which
        stays within max_pending distinct keys: returns how many counts did
        not fit and were dropped."""
        lost = 0
        with self._lock:
            for key, n in batch.items():
                if key in self._pending or len(self._pending) < self.max_pending:
                    self._pending[key] += n
                else:
                    lost += n
        return lost
