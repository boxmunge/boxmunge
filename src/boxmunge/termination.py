# SPDX-License-Identifier: Apache-2.0
"""Turn SIGTERM into an unwinding exception for the CLI.

systemd stops a unit (shutdown, the unattended-upgrades reboot window,
`systemctl stop`) with SIGTERM, whose default action ends Python without
running ``finally`` blocks or context-manager exits. A backup interrupted
that way left its plaintext dump on disk and its dump running in the
container. Raising instead lets every cleanup run before the process exits.

``Terminated`` derives from BaseException, not SystemExit: the MCP tool
wrappers catch SystemExit from commands to turn exit codes into results,
and must not swallow a request to stop the whole process.
"""

from __future__ import annotations

import signal
from collections.abc import Iterator
from contextlib import contextmanager


class Terminated(BaseException):
    def __init__(self, signum: int) -> None:
        super().__init__(f"terminated by signal {signum}")
        self.signum = signum


def _raise_terminated(signum: int, _frame: object) -> None:
    raise Terminated(signum)


@contextmanager
def sigterm_unwinds() -> Iterator[None]:
    previous = signal.signal(signal.SIGTERM, _raise_terminated)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)
