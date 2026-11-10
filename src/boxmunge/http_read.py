# SPDX-License-Identifier: Apache-2.0
"""Read an HTTP response body under a size cap and a total deadline.

A socket timeout bounds each read, not the whole body: a server that sends a
byte inside every timeout could hold the reader (as root, often with
upgrade.lock held) for days. read1 does at most one read of the socket, so
the deadline is checked between reads and overrun by one timeout at most.
"""
from __future__ import annotations

import time
from typing import Any

_CHUNK = 64 * 1024


class ReadDeadline(TimeoutError):
    """The whole body took longer than its deadline."""


def read_within(resp: Any, max_bytes: int, seconds: float) -> bytes:
    """Up to `max_bytes` of the body (stopping there: a caller that passes
    its limit plus one can tell an oversized body); raises TimeoutError when
    the body takes longer than `seconds` (ReadDeadline)."""
    deadline = time.monotonic() + seconds
    chunks: list[bytes] = []
    size = 0
    while size < max_bytes:
        if time.monotonic() > deadline:
            raise ReadDeadline(f"the response did not finish within {seconds:.0f}s")
        chunk = resp.read1(min(_CHUNK, max_bytes - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)
