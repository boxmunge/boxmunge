# SPDX-License-Identifier: Apache-2.0
"""A secret's value for `secrets set KEY`: read it, and refuse (CliExit,
before anything is sent) one the server could not store as it was meant.

No message ever echoes the value.
"""

from __future__ import annotations

import getpass
import sys

from boxmunge_cli.exitcodes import FAILURE, USAGE, CliExit

MAX_VALUE_BYTES = 64 * 1024


def read_value(key: str) -> str:
    """Prompted without echo at a terminal; else all of stdin, read as bytes
    so the locale cannot reinterpret them, less one trailing newline. A
    second line stays in, to be refused as a line break rather than dropped.
    Reads at most the limit plus a byte and a newline."""
    if sys.stdin is not None and sys.stdin.isatty():
        return getpass.getpass(f"Value for {key}: ")
    raw = sys.stdin.buffer.read(MAX_VALUE_BYTES + 2) if sys.stdin is not None else b""
    if not raw:
        raise CliExit(FAILURE, f"no value for {key} on stdin. Nothing was sent. Pipe it "
                               f"in as one line, or run at a terminal to be asked for it.")
    try:
        return raw.removesuffix(b"\n").decode("utf-8")
    except UnicodeDecodeError:
        raise CliExit(USAGE, _not_utf8(key)) from None


def checked_value(key: str, value: str) -> bytes:
    """The value as the UTF-8 bytes to send; CliExit if it cannot be a secret."""
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:  # undecodable bytes in argv arrive as surrogates
        raise CliExit(USAGE, _not_utf8(key)) from None
    if "\n" in value or "\r" in value:
        raise CliExit(USAGE, f"the value for {key} contains a line break, which a secret "
                             f"cannot hold. Nothing was sent.")
    if len(encoded) > MAX_VALUE_BYTES:
        raise CliExit(USAGE, f"the value for {key} is over 64 KiB, the most a secret "
                             f"holds. Nothing was sent.")
    return encoded


def _not_utf8(key: str) -> str:
    return f"the value for {key} must be UTF-8 text. Nothing was sent."
