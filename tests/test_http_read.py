# SPDX-License-Identifier: Apache-2.0
"""read_within: a response body read with a size cap and a total deadline,
so a server that trickles (one byte inside every per-read timeout) cannot
hold the reader, and the lock it holds, for days."""
from __future__ import annotations

import io

import pytest

from boxmunge import http_read
from boxmunge.http_read import read_within


class _Trickle:
    """A body served `step` bytes per read1, each read taking `secs`."""

    def __init__(self, body: bytes, step: int, clock: list[float], secs: float) -> None:
        self._body, self._step, self._clock, self._secs = io.BytesIO(body), step, clock, secs

    def read1(self, n: int) -> bytes:
        self._clock[0] += self._secs
        return self._body.read(min(n, self._step))


@pytest.fixture
def clock(monkeypatch) -> list[float]:
    now = [1000.0]
    monkeypatch.setattr(http_read.time, "monotonic", lambda: now[0])
    return now


def test_the_whole_body_within_the_limits(clock) -> None:
    assert read_within(_Trickle(b"x" * 300, 100, clock, 1), 1000, 60) == b"x" * 300


def test_reading_stops_at_max_bytes(clock) -> None:
    resp = _Trickle(b"x" * 5000, 100, clock, 0)
    assert read_within(resp, 1001, 60) == b"x" * 1001


def test_a_trickling_body_is_cut_off_at_the_deadline(clock) -> None:
    resp = _Trickle(b"x" * 1000, 1, clock, 9)  # inside any per-read timeout
    with pytest.raises(TimeoutError, match="did not finish within 60s"):
        read_within(resp, 10_000, 60)
    assert clock[0] - 1000 <= 69  # the deadline, plus at most one read
