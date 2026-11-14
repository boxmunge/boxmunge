# SPDX-License-Identifier: Apache-2.0
"""Run a process whose output is drained as it comes and retained in part.

``subprocess.run(capture_output=True)`` keeps everything a command prints in
this process, so a noisy command (or one that echoes application-controlled
content) makes a root health run allocate as much as the command cares to
print, and strict text decoding lets one stray byte raise before the exit
status is read. Here each captured stream is drained continuously on its own
thread (so neither pipe can fill and stall the command), only its first
``keep`` bytes are retained, and it is decoded with replacement. A stream
past ``budget`` bytes in total gets the command killed: OutputBudgetExceeded.
A stream still open DRAIN_GRACE after the process ended: OutputNotClosed.
A stream that is not a pipe (a file, None) is left to the child.
"""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path
from typing import IO, Any

_CHUNK = 65536


# Seconds the drains get to reach EOF once the process has exited or been killed.
DRAIN_GRACE = 2.0


class OutputError(subprocess.SubprocessError):
    """A captured stream could not be collected; ``reason`` says why."""

    def __init__(self, cmd: Any, reason: str) -> None:
        self.cmd, self.reason = cmd, reason
        super().__init__(reason)


class OutputBudgetExceeded(OutputError):
    """A captured stream carried more than its budget; the process was killed."""

    def __init__(self, cmd: Any, stream: str, budget: int) -> None:
        self.stream, self.budget = stream, budget
        super().__init__(cmd, f"wrote more than {budget} bytes on {stream}")


class OutputNotClosed(OutputError):
    """The process ended but something it started still holds a captured
    stream open (a background child inherited the pipe)."""

    def __init__(self, cmd: Any, stream: str) -> None:
        self.stream = stream
        super().__init__(cmd, f"left {stream} open after it exited")


class _Drain(threading.Thread):
    def __init__(self, name: str, pipe: IO[bytes], keep: int, budget: int,
                 proc: subprocess.Popen) -> None:
        super().__init__(daemon=True)
        self.stream, self.pipe, self.keep, self.budget, self.proc = name, pipe, keep, budget, proc
        self.kept = bytearray()
        self.exceeded = False
        self.error: BaseException | None = None

    def run(self) -> None:
        total = 0
        try:
            while chunk := self.pipe.read1(_CHUNK):
                total += len(chunk)
                if len(self.kept) < self.keep:
                    self.kept += chunk[: self.keep - len(self.kept)]
                if total > self.budget and not self.exceeded:
                    self.exceeded = True
                    self.proc.kill()  # keep draining to EOF, so nothing blocks
        except BaseException as e:  # re-raised by run_bounded: never lost with the thread
            self.error = e


def run_bounded(
    cmd: list[str], *, timeout: float, keep: int, budget: int,
    cwd: Path | None = None, env: Any = None, stdin: Any = None,
    stdout: Any = None, stderr: Any = None, capture_output: bool = False,
    text: bool = False,
) -> subprocess.CompletedProcess:
    """Like subprocess.run, which it matches for what it raises on a timeout
    (TimeoutExpired, the process killed). Each captured stream comes back
    as at most ``keep`` bytes (str if ``text``, decoded with replacement);
    raises OutputBudgetExceeded for one that carried more than ``budget``."""
    if capture_output:
        stdout = stderr = subprocess.PIPE
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=stdin, stdout=stdout, stderr=stderr)
    drains = [_Drain(name, pipe, keep, budget, proc)
              for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)) if pipe]
    for d in drains:
        d.start()
    try:
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            _join(drains)
            raise subprocess.TimeoutExpired(cmd, timeout) from None
    finally:
        if proc.poll() is None:  # interrupted
            proc.kill()
            proc.wait()
    held = _join(drains)
    for d in drains:
        if d.error is not None:
            raise d.error
        if d.exceeded:
            raise OutputBudgetExceeded(cmd, d.stream, budget)
    if held:
        raise OutputNotClosed(cmd, held[0].stream)
    out = {d.stream: _decode(d.kept, text) for d in drains}
    return subprocess.CompletedProcess(cmd, proc.returncode, out.get("stdout"), out.get("stderr"))


def _join(drains: list[_Drain]) -> list[_Drain]:
    """Wait for the drains, a grace period in all; those still reading."""
    deadline = time.monotonic() + DRAIN_GRACE
    for d in drains:
        d.join(max(0.0, deadline - time.monotonic()))
    return [d for d in drains if d.is_alive()]


def _decode(kept: bytearray, text: bool) -> Any:
    if not text:
        return bytes(kept)
    # As text=True did: universal newlines.
    return bytes(kept).decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
