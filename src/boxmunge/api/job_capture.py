# SPDX-License-Identifier: Apache-2.0
"""A job's output, captured at the file-descriptor level, and the message
a failed core leaves.

The core a job runs calls compose and docker, which write to the
descriptors they inherit, not to Python's sys.stdout. So capture_output
puts a pipe over fds 1 and 2 themselves (and /dev/null over fd 0, so a
prompt fails at once instead of waiting for an answer nobody can give). A
reader thread hands each line on and echoes it to the original fd 1, the
journal. A grandchild that outlives the core (a detached `compose logs -f`,
a hung build) keeps the pipe open; the capture then stops waiting after
CAPTURE_DRAIN_SECONDS and says the output was cut off.
"""
from __future__ import annotations

import os
import selectors
import sys
import threading
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass

CAPTURE_DRAIN_SECONDS = 5
OUTPUT_TAIL_LINES = 20
FAILURE_MESSAGE_CAP = 1000
_POLL_SECONDS = 0.1
_ERROR_LINES_SHOWN = 3


@dataclass
class CaptureResult:
    """Filled in when the capture block exits. cut_off: the pipe was still
    held open (by a process that outlived the block) when the capture
    stopped waiting, so later output was not seen."""

    cut_off: bool = False


class OutputTail(deque):
    """The last OUTPUT_TAIL_LINES lines of a job's output."""

    def __init__(self) -> None:
        super().__init__(maxlen=OUTPUT_TAIL_LINES)


class CoreFailed(Exception):
    """The core a job ran exited non-zero."""

    def __init__(self, verb: str, rc: int) -> None:
        super().__init__(f"`{verb}` exited {rc}")
        self.verb = verb
        self.rc = rc


def failure_message(verb: str, rc: int, tail: Sequence[str], *, job_id: str) -> str:
    """What a failed core says: the last few ERROR: lines of its output
    (the last few lines when there are none), then where the rest is. At
    most FAILURE_MESSAGE_CAP characters; the pointer always survives."""
    errors = [line for line in tail if line.startswith("ERROR:")]
    shown = (errors or list(tail))[-_ERROR_LINES_SHOWN:]
    head = f"`{verb}` exited {rc}: "
    pointer = f" Full output: boxmunge job show {job_id} --events."
    body = " / ".join(shown) if shown else "(no output)"
    room = FAILURE_MESSAGE_CAP - len(head) - len(pointer)
    if len(body) > room:
        body = body[:room - 1] + "…"
    return head + body + pointer


@contextmanager
def capture_output(on_line: Callable[[str], None]) -> Iterator[CaptureResult]:
    """Inside the block, everything written to fds 1 and 2 (by this
    process or any child) reaches *on_line* one line at a time, decoded
    as UTF-8 with undecodable bytes replaced, and is echoed to the
    original fd 1. On exit the descriptors and sys.stdout/sys.stderr are
    restored. An exception *on_line* raised is raised here once they are,
    and no line after it is handed on (output is still drained and echoed,
    so writers never block on a full pipe)."""
    for stream in (sys.stdout, sys.stderr):
        stream.flush()
    saved = [os.dup(fd) for fd in (0, 1, 2)]
    read_end, write_end = os.pipe()
    null = os.open(os.devnull, os.O_RDONLY)
    reader = _Reader(read_end, saved[1], on_line)
    streams = sys.stdout, sys.stderr
    result = CaptureResult()
    unclosed = [write_end, null]
    try:
        os.dup2(null, 0)
        os.dup2(write_end, 1)
        os.dup2(write_end, 2)
        while unclosed:
            os.close(unclosed.pop())
        reader.start()
        sys.stdout, sys.stderr = (os.fdopen(fd, "w", buffering=1, encoding="utf-8",
                                            errors="replace", closefd=False) for fd in (1, 2))
        yield result
    finally:
        for wrapper in (sys.stdout, sys.stderr):
            if wrapper not in streams:
                wrapper.close()
        sys.stdout, sys.stderr = streams
        for fd, copy in zip((0, 1, 2), saved):
            os.dup2(copy, fd)
        for fd in unclosed:
            os.close(fd)
        if reader.is_alive():
            result.cut_off = not reader.finish(CAPTURE_DRAIN_SECONDS)
        for fd in (*saved, read_end):
            os.close(fd)
    if reader.error is not None:
        raise reader.error


class _Reader(threading.Thread):
    """Reads the capture pipe until every writer has closed it, or until
    told to stop."""

    def __init__(self, fd: int, echo_fd: int, on_line: Callable[[str], None]) -> None:
        super().__init__(name="job-output-capture", daemon=True)
        self._fd = fd
        self._echo_fd = echo_fd
        self._on_line = on_line
        self._stop_reading = threading.Event()
        self.error: BaseException | None = None

    def finish(self, seconds: float) -> bool:
        """Wait up to *seconds* for the writers to close the pipe; whether
        they did. If not, the reader stops and its remaining output is lost."""
        self.join(seconds)
        if not self.is_alive():
            return True
        self._stop_reading.set()
        self.join()
        return False

    def run(self) -> None:
        try:
            self._read_until_closed()
        except Exception as e:  # noqa: BLE001 - raised by capture_output on exit
            self.error = self.error or e

    def _read_until_closed(self) -> None:
        pending = b""
        with selectors.DefaultSelector() as selector:
            selector.register(self._fd, selectors.EVENT_READ)
            while not self._stop_reading.is_set():
                if not selector.select(_POLL_SECONDS):
                    continue
                chunk = os.read(self._fd, 65536)
                if not chunk:
                    break
                *lines, pending = (pending + chunk).split(b"\n")
                for line in lines:
                    self._emit(line)
        if pending:
            self._emit(pending)

    def _emit(self, raw: bytes) -> None:
        os.write(self._echo_fd, raw + b"\n")
        if self.error is not None:
            return
        try:
            self._on_line(raw.decode("utf-8", errors="replace"))
        except Exception as e:  # noqa: BLE001 - raised by capture_output on exit
            self.error = e
