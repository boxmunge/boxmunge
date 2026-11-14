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
A stream that is not a pipe (a file, None) is left to the child.
"""

from __future__ import annotations

import subprocess
import threading
from pathlib import Path
from typing import IO, Any

_CHUNK = 65536


class OutputBudgetExceeded(subprocess.SubprocessError):
    """A captured stream carried more than its budget; the process was killed."""

    def __init__(self, cmd: Any, stream: str, budget: int) -> None:
        self.cmd, self.stream, self.budget = cmd, stream, budget
        super().__init__(f"{stream} exceeded {budget} bytes")


class _Drain(threading.Thread):
    def __init__(self, name: str, pipe: IO[bytes], keep: int, budget: int,
                 proc: subprocess.Popen) -> None:
        super().__init__(daemon=True)
        self.stream, self.pipe, self.keep, self.budget, self.proc = name, pipe, keep, budget, proc
        self.kept = bytearray()
        self.exceeded = False

    def run(self) -> None:
        total = 0
        while chunk := self.pipe.read1(_CHUNK):
            total += len(chunk)
            if len(self.kept) < self.keep:
                self.kept += chunk[: self.keep - len(self.kept)]
            if total > self.budget and not self.exceeded:
                self.exceeded = True
                self.proc.kill()  # keep draining to EOF, so nothing blocks


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
            raise subprocess.TimeoutExpired(cmd, timeout) from None
    finally:
        if proc.poll() is None:  # interrupted
            proc.kill()
            proc.wait()
        for d in drains:
            d.join()
    for d in drains:
        if d.exceeded:
            raise OutputBudgetExceeded(cmd, d.stream, budget)
    out = {d.stream: bytes(d.kept).decode("utf-8", errors="replace") if text else bytes(d.kept)
           for d in drains}
    return subprocess.CompletedProcess(cmd, proc.returncode, out.get("stdout"), out.get("stderr"))
