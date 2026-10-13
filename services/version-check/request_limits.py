"""Abuse limits for the public version-check service.

- client_key: the rate-limit key for a client address (IPv6 by /64, since one
  host commonly owns a whole /64).
- RateLimiter: fixed-window per-client request limit with bounded memory.
- CheckCounter: aggregates /v1/check counts in memory and flushes them to
  SQLite periodically, so an unauthenticated request never waits on a write.

Both are per-process (gunicorn runs several workers); limits are therefore
per worker, and each worker flushes its own counts. Counts recorded since a
worker's last flush are lost if it is killed without a clean exit.
"""

import atexit
import ipaddress
import sqlite3
import threading
import time
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Callable


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
    until the sweep frees room.
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

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            if now - self._last_sweep >= self.window:
                self._windows = {k: v for k, v in self._windows.items()
                                 if now - v[0] < self.window}
                self._last_sweep = now
            started, count = self._windows.get(key, (now, 0))
            if now - started >= self.window:
                started, count = now, 0
            if key not in self._windows and len(self._windows) >= self.max_clients:
                return False
            if count >= self.limit:
                return False
            self._windows[key] = (started, count + 1)
            return True


class CheckCounter:
    """Daily per-version check counts, buffered in memory.

    record() never touches the database unless the buffer is due: every
    `flush_interval` seconds, or immediately when `max_pending` distinct
    (date, version) keys are buffered. flush() runs at process exit too.
    """

    def __init__(self, db_path: Path, flush_interval: float, max_pending: int,
                 clock: Callable[[], float] = time.monotonic,
                 today: Callable[[], date] = date.today) -> None:
        self.db_path = db_path
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
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executemany(
                """INSERT INTO version_checks (date, version, count)
                   VALUES (?, ?, ?)
                   ON CONFLICT (date, version) DO UPDATE SET count = count + excluded.count""",
                [(d, v, n) for (d, v), n in pending.items()],
            )
            conn.commit()
        finally:
            conn.close()
