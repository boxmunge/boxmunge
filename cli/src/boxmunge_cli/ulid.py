"""ULID generation — Universally Unique Lexicographically Sortable Identifier."""
import os
import time

_ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

_last_ms: int = 0
_last_rand: int = 0


def generate_ulid() -> str:
    """Generate a new ULID string.

    Monotonicity is guaranteed within the same millisecond by incrementing
    the random component rather than drawing a fresh random value.
    """
    global _last_ms, _last_rand

    timestamp_ms = int(time.time() * 1000)

    if timestamp_ms <= _last_ms:
        _last_rand += 1
        randomness = _last_rand
        timestamp_ms = _last_ms
    else:
        randomness = int.from_bytes(os.urandom(10), byteorder="big")
        _last_ms = timestamp_ms
        _last_rand = randomness

    t_chars = []
    t = timestamp_ms
    for _ in range(10):
        t_chars.append(_ENCODING[t & 0x1F])
        t >>= 5
    t_chars.reverse()

    r_chars = []
    r = randomness
    for _ in range(16):
        r_chars.append(_ENCODING[r & 0x1F])
        r >>= 5
    r_chars.reverse()

    return "".join(t_chars) + "".join(r_chars)
