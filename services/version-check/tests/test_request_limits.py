"""Unit tests for request_limits: client keys, rate limiter, check counter."""

import sqlite3
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from request_limits import (  # noqa: E402
    FULL, LIMITED, NETWORK_LIMITED, CheckCounter, RateLimiter, RequestLimiter, client_key,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class TestClientKey:
    def test_ipv4_is_its_own_key(self) -> None:
        assert client_key("203.0.113.7") == "203.0.113.7"

    def test_ipv6_is_keyed_by_slash_64(self) -> None:
        assert client_key("2001:db8:1:2:aaaa::1") == client_key("2001:db8:1:2:bbbb::9")
        assert client_key("2001:db8:1:2::1") != client_key("2001:db8:1:3::1")

    def test_ipv4_mapped_ipv6_is_the_ipv4_address(self) -> None:
        assert client_key("::ffff:203.0.113.7") == "203.0.113.7"

    def test_missing_address(self) -> None:
        assert client_key(None) == "unknown"


class TestRateLimiter:
    def test_allows_up_to_limit_then_refuses(self) -> None:
        clock = FakeClock()
        rl = RateLimiter(limit=3, window=60, max_clients=10, clock=clock)
        assert [rl.allow("a") for _ in range(4)] == [True, True, True, False]

    def test_clients_are_independent(self) -> None:
        rl = RateLimiter(limit=1, window=60, max_clients=10, clock=FakeClock())
        assert rl.allow("a") and rl.allow("b")
        assert not rl.allow("a")

    def test_window_resets(self) -> None:
        clock = FakeClock()
        rl = RateLimiter(limit=1, window=60, max_clients=10, clock=clock)
        assert rl.allow("a") and not rl.allow("a")
        clock.now += 60
        assert rl.allow("a")

    def test_memory_bounded_fail_closed_then_swept(self) -> None:
        clock = FakeClock()
        rl = RateLimiter(limit=5, window=60, max_clients=2, clock=clock)
        assert rl.allow("a") and rl.allow("b")
        assert not rl.allow("c"), "a third client must be refused while the table is full"
        assert rl.allow("a"), "tracked clients keep their allowance"
        clock.now += 60
        assert rl.allow("c"), "the sweep frees expired windows"

    def test_rejects_nonsense_configuration(self) -> None:
        with pytest.raises(ValueError):
            RateLimiter(limit=0, window=60, max_clients=1)


def _db(tmp_path: Path) -> Path:
    path = tmp_path / "checks.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE version_checks (date TEXT NOT NULL, version TEXT NOT NULL, "
                 "count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (date, version))")
    conn.commit()
    conn.close()
    return path


def _rows(path: Path) -> dict:
    conn = sqlite3.connect(path)
    try:
        return {(d, v): c for d, v, c in conn.execute("SELECT date, version, count FROM version_checks")}
    finally:
        conn.close()


class TestCheckCounter:
    def test_buffers_until_interval_elapses(self, tmp_path) -> None:
        db, clock = _db(tmp_path), FakeClock()
        counter = CheckCounter(db, flush_interval=60, max_pending=100, clock=clock,
                               today=lambda: date(2026, 10, 13))
        counter.record("0.3.0")
        counter.record("0.3.0")
        assert _rows(db) == {}
        clock.now += 60
        counter.record("0.3.1")
        assert _rows(db) == {("2026-10-13", "0.3.0"): 2, ("2026-10-13", "0.3.1"): 1}

    def test_flush_adds_to_existing_counts(self, tmp_path) -> None:
        db = _db(tmp_path)
        counter = CheckCounter(db, flush_interval=3600, max_pending=100, clock=FakeClock(),
                               today=lambda: date(2026, 10, 13))
        for _ in range(3):
            counter.record("0.3.0")
            counter.flush()
        assert _rows(db) == {("2026-10-13", "0.3.0"): 3}

    def test_flushes_early_when_too_many_keys_pending(self, tmp_path) -> None:
        db = _db(tmp_path)
        counter = CheckCounter(db, flush_interval=3600, max_pending=2, clock=FakeClock(),
                               today=lambda: date(2026, 10, 13))
        counter.record("0.3.0")
        assert _rows(db) == {}
        counter.record("0.3.1")
        assert len(_rows(db)) == 2

    def test_days_are_utc_dates_whatever_the_local_zone(self, tmp_path, local_date_not_utc) -> None:
        db = _db(tmp_path)
        counter = CheckCounter(db, flush_interval=3600, max_pending=100, clock=FakeClock())
        counter.record("0.3.0")
        counter.flush()
        assert _rows(db) == {(datetime.now(timezone.utc).date().isoformat(), "0.3.0"): 1}

    def test_empty_flush_does_not_touch_the_database(self, tmp_path) -> None:
        counter = CheckCounter(tmp_path / "absent" / "checks.db", flush_interval=60,
                               max_pending=10, clock=FakeClock())
        counter.flush()  # would raise if it tried to open the missing directory


class TestExhausted:
    def test_reports_a_used_up_window_without_counting(self):
        now = [0.0]
        limiter = RateLimiter(2, 10, 100, clock=lambda: now[0])
        assert not limiter.exhausted("a")
        limiter.allow("a")
        assert not limiter.exhausted("a")
        limiter.allow("a")
        assert limiter.exhausted("a") and not limiter.exhausted("b")
        now[0] = 10.0
        assert not limiter.exhausted("a")


class TestAdmit:
    def test_says_why_it_refused(self):
        rl = RateLimiter(limit=1, window=60, max_clients=1, clock=FakeClock())
        assert rl.admit("a") is None
        assert rl.admit("a") == LIMITED
        assert rl.admit("b") == FULL

    def test_full_for_counts_nothing_and_sees_the_sweep(self):
        clock = FakeClock()
        rl = RateLimiter(limit=5, window=60, max_clients=1, clock=clock)
        assert not rl.full_for("a")
        rl.allow("a")
        assert rl.full_for("b") and not rl.full_for("a")
        clock.now += 60
        assert not rl.full_for("b"), "an expired window frees its slot"


def _network(addr):
    return addr.rsplit(".", 1)[0] + ".0/24"


class TestRequestLimiter:
    def _limiter(self, clock, per_network=2):
        return RequestLimiter(per_client=3, per_network=per_network, window=60,
                              max_clients=2, network_of=_network, clock=clock)

    def test_tracked_clients_get_their_own_limit(self):
        limiter = self._limiter(FakeClock())
        assert [limiter.allow("198.51.100.1") for _ in range(4)] == [True, True, True, False]

    def test_a_full_client_table_limits_new_clients_by_network(self):
        """One network filling the client table exhausts only that network."""
        limiter = self._limiter(FakeClock())
        assert limiter.allow("203.0.113.1") and limiter.allow("203.0.113.2")
        assert [limiter.allow(f"203.0.113.{n}") for n in (3, 4, 5)] == [True, True, False]
        assert limiter.allow("198.51.100.7"), "a box on another network still gets through"

    def test_refuses_a_new_client_once_both_tables_are_full(self):
        limiter = self._limiter(FakeClock(), per_network=5)
        limiter.allow("203.0.113.1")
        limiter.allow("203.0.114.1")
        assert limiter.allow("203.0.115.1") and limiter.allow("203.0.116.1")
        assert not limiter.allow("203.0.117.1")

    def test_refusal_counts_nothing_and_says_which_table_refused(self):
        limiter = self._limiter(FakeClock(), per_network=1)
        assert limiter.refusal("203.0.113.1") is None
        for _ in range(3):
            limiter.admit("203.0.113.1")
        assert limiter.refusal("203.0.113.1") == LIMITED
        limiter.admit("203.0.113.2")
        assert limiter.refusal("203.0.113.3") is None, "the network table has room"
        assert limiter.admit("203.0.113.3") is None
        assert limiter.refusal("203.0.113.4") == NETWORK_LIMITED
        assert limiter.admit("203.0.113.4") == NETWORK_LIMITED
        limiter.admit("198.51.100.1")
        assert limiter.refusal("192.0.2.1") == FULL

    def test_a_client_over_its_own_limit_is_not_sent_to_the_network_table(self):
        limiter = self._limiter(FakeClock())
        for _ in range(3):
            limiter.allow("198.51.100.1")
        assert not limiter.allow("198.51.100.1")
