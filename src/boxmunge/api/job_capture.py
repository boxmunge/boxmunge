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

from boxmunge.api.job_events import MAX_EVENT_MESSAGE

CAPTURE_DRAIN_SECONDS = 5
OUTPUT_TAIL_LINES = 20
FAILURE_MESSAGE_CAP = 1000
_POLL_SECONDS = 0.1
# The longest piece of output handed on as one line: an event message is
# cut at MAX_EVENT_MESSAGE characters anyway, and output that never ends a
# line must not be buffered without limit.
MAX_LINE_BYTES = MAX_EVENT_MESSAGE
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


# fds 0-2 and sys.stdout/sys.stderr belong to the whole process: two
# captures at once would restore each other's descriptors out of order.
_ACTIVE = threading.Lock()


@contextmanager
def capture_output(on_line: Callable[[str], None]) -> Iterator[CaptureResult]:
    """Inside the block, everything written to fds 1 and 2 (by this
    process or any child) reaches *on_line* one line at a time, decoded
    as UTF-8 with undecodable bytes replaced, and is echoed to the
    original fd 1. A line longer than MAX_LINE_BYTES (a progress bar that
    never prints a newline) is handed on in pieces of at most that size.
    On exit the descriptors and sys.stdout/sys.stderr are restored.

    The pipe is always drained, so a writer never blocks on it: if
    *on_line* raises, later lines are still echoed; if the echo fails (the
    journal is gone), later lines still reach *on_line*. Either first
    failure is raised here once the descriptors are restored.

    One capture at a time per process: a second one raises RuntimeError."""
    if not _ACTIVE.acquire(blocking=False):
        raise RuntimeError("capture_output is already active in this process; a job's "
                           "output can only be captured by one block at a time")
    try:
        yield from _capture(on_line)
    finally:
        _ACTIVE.release()


def _capture(on_line: Callable[[str], None]) -> Iterator[CaptureResult]:
    for stream in (sys.stdout, sys.stderr):
        stream.flush()
    saved = [os.dup(fd) for fd in (0, 1, 2)]
    read_end, write_end = os.pipe()
    null = os.open(os.devnull, os.O_RDONLY)
    # The reader closes these itself when it ends: one stuck past the
    # drain time must not have its descriptors closed (and reused) under it.
    reader_fds = [read_end, os.dup(saved[1])]
    reader = _Reader(*reader_fds, on_line)
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
        reader_fds = []
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
        for fd in (*unclosed, *reader_fds, *saved):
            os.close(fd)
        if reader.is_alive():
            result.cut_off = not reader.finish(CAPTURE_DRAIN_SECONDS)
    if reader.error is not None:
        raise reader.error


class _Reader(threading.Thread):
    """Reads the capture pipe until every writer has closed it, or until
    told to stop. Owns (and closes) the pipe's read end and its echo fd."""

    def __init__(self, fd: int, echo_fd: int, on_line: Callable[[str], None]) -> None:
        super().__init__(name="job-output-capture", daemon=True)
        self._fd = fd
        self._echo_fd: int | None = echo_fd
        self._on_line: Callable[[str], None] | None = on_line
        self._stop_reading = threading.Event()
        self.error: BaseException | None = None

    def finish(self, seconds: float) -> bool:
        """Wait up to *seconds* for the writers to close the pipe; whether
        they did. If not, the reader is told to stop and given one poll
        interval more; its remaining output is lost, and a reader stuck in
        a handler is left to end on its own."""
        self.join(seconds)
        if not self.is_alive():
            return True
        self._stop_reading.set()
        self.join(_POLL_SECONDS * 2)
        return False

    def run(self) -> None:
        try:
            self._read_until_closed()
        except Exception as e:  # noqa: BLE001 - raised by capture_output on exit
            self._failed(e)
        finally:
            os.close(self._fd)
            if self._echo_fd is not None:
                os.close(self._echo_fd)

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
                    self._emit_cut(line)
                while len(pending) > MAX_LINE_BYTES:
                    self._emit(pending[:MAX_LINE_BYTES])
                    pending = pending[MAX_LINE_BYTES:]
        if pending:
            self._emit(pending)

    def _emit_cut(self, raw: bytes) -> None:
        for start in range(0, max(len(raw), 1), MAX_LINE_BYTES):
            self._emit(raw[start:start + MAX_LINE_BYTES])

    def _emit(self, raw: bytes) -> None:
        if self._echo_fd is not None:
            try:
                _write_all(self._echo_fd, raw + b"\n")
            except OSError as e:
                self._failed(e)
                os.close(self._echo_fd)
                self._echo_fd = None
        if self._on_line is None or self._stop_reading.is_set():
            return
        try:
            self._on_line(raw.decode("utf-8", errors="replace"))
        except Exception as e:  # noqa: BLE001 - raised by capture_output on exit
            self._failed(e)
            self._on_line = None

    def _failed(self, error: BaseException) -> None:
        """Keep the first failure; capture_output raises it on exit."""
        if self.error is None:
            self.error = error


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]
