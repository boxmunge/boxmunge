# SPDX-License-Identifier: Apache-2.0
"""fd-level output capture, the output tail, and the core-failure message."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time

import pytest

from boxmunge.api import job_capture
from boxmunge.api.job_capture import (
    CAPTURE_DRAIN_SECONDS, MAX_LINE_BYTES, OUTPUT_TAIL_LINES, CoreFailed, OutputTail,
    capture_output, failure_message,
)


def _fds() -> list[tuple[int, int]]:
    return [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in (0, 1, 2)]


def test_capture_sees_output_of_a_subprocess_writing_to_inherited_fds() -> None:
    lines: list[str] = []
    with capture_output(lines.append) as result:
        subprocess.run(["sh", "-c", "echo out; echo err >&2"], check=True)
    assert sorted(lines) == ["err", "out"]
    assert result.cut_off is False


def test_capture_sees_print_and_restores_fds() -> None:
    before = _fds()
    stdout, stderr = sys.stdout, sys.stderr
    lines: list[str] = []
    with capture_output(lines.append):
        print("from print")
        print("to stderr", file=sys.stderr)
        os.write(1, "raw bytes \xff\n".encode("latin-1"))
    assert lines == ["from print", "to stderr", "raw bytes �"]
    assert _fds() == before
    assert (sys.stdout, sys.stderr) == (stdout, stderr)


def test_a_last_line_without_a_newline_is_still_seen() -> None:
    lines: list[str] = []
    with capture_output(lines.append):
        subprocess.run(["printf", "partial"], check=True)
    assert lines == ["partial"]


def test_capture_returns_when_a_grandchild_keeps_the_pipe_open() -> None:
    lines: list[str] = []
    started = time.monotonic()
    with capture_output(lines.append) as result:
        subprocess.run(["sh", "-c", "sleep 30 & echo $!"], check=True)
    elapsed = time.monotonic() - started
    try:
        assert result.cut_off is True
        assert elapsed < CAPTURE_DRAIN_SECONDS + 1
    finally:
        os.kill(int(lines[0]), signal.SIGTERM)


def test_input_fails_instead_of_waiting() -> None:
    lines: list[str] = []
    with capture_output(lines.append):
        subprocess.run(["sh", "-c", "read answer || echo no input"], timeout=5)
    assert lines == ["no input"]


def test_a_failing_line_handler_is_raised_after_the_fds_are_restored() -> None:
    before = _fds()

    def broken(_line: str) -> None:
        raise RuntimeError("handler broke")

    with pytest.raises(RuntimeError, match="handler broke"):
        with capture_output(broken):
            print("first")
            print("second")
    assert _fds() == before


BROKEN_JOURNAL_BOUND_SECONDS = 30


def test_a_broken_journal_still_drains_and_raises_on_exit() -> None:
    """With the echo target gone, the core must not block on a full pipe:
    every line still reaches the handler, and the echo failure is raised.
    The capture runs in a thread joined with a bound, so a regression that
    blocks fails here instead of hanging the suite."""
    journal_read, journal_write = os.pipe()
    os.close(journal_read)
    real_stdout = os.dup(1)
    os.dup2(journal_write, 1)
    os.close(journal_write)
    lines: list[str] = []
    raised: list[BaseException] = []

    def run() -> None:
        try:
            with capture_output(lines.append):
                for n in range(2000):
                    print(f"{n:04d}" + "x" * 100)
        except BaseException as e:  # handed to the test thread below
            raised.append(e)

    worker = threading.Thread(target=run, daemon=True)
    try:
        worker.start()
        worker.join(BROKEN_JOURNAL_BOUND_SECONDS)
    finally:
        os.dup2(real_stdout, 1)
        os.close(real_stdout)
    assert not worker.is_alive(), f"capture still blocked after {BROKEN_JOURNAL_BOUND_SECONDS}s"
    assert len(raised) == 1 and isinstance(raised[0], BrokenPipeError), raised
    assert len(lines) == 2000 and lines[-1].startswith("1999")


def test_a_second_capture_in_the_same_process_is_refused() -> None:
    lines: list[str] = []
    with capture_output(lines.append):
        with pytest.raises(RuntimeError, match="already"):
            with capture_output(lines.append):
                pass
        print("outer still works")
    assert lines == ["outer still works"]
    with capture_output(lines.append):
        print("and a later one too")
    assert lines[-1] == "and a later one too"


def test_exit_is_bounded_when_the_handler_is_stuck(monkeypatch) -> None:
    monkeypatch.setattr(job_capture, "CAPTURE_DRAIN_SECONDS", 1)
    release = threading.Event()
    started = time.monotonic()
    try:
        with capture_output(lambda _line: release.wait(30)) as result:
            print("one line")
        elapsed = time.monotonic() - started
    finally:
        release.set()
    assert result.cut_off is True
    assert elapsed < 2


def test_output_without_newlines_is_handed_on_in_bounded_pieces() -> None:
    lines: list[str] = []
    with capture_output(lines.append):
        os.write(1, b"y" * (MAX_LINE_BYTES * 3 + 7))
    assert all(len(line) <= MAX_LINE_BYTES for line in lines)
    assert "".join(lines) == "y" * (MAX_LINE_BYTES * 3 + 7)


def test_output_tail_keeps_the_last_lines() -> None:
    tail = OutputTail()
    tail.extend(str(n) for n in range(OUTPUT_TAIL_LINES + 5))
    assert list(tail) == [str(n) for n in range(5, OUTPUT_TAIL_LINES + 5)]


def test_core_failed_names_the_verb_and_code() -> None:
    error = CoreFailed("deploy", 2)
    assert (error.verb, error.rc) == ("deploy", 2)
    assert "deploy" in str(error) and "2" in str(error)


def test_failure_message_prefers_error_lines() -> None:
    tail = ["pulling", "ERROR: one", "noise", "ERROR: two", "ERROR: three", "ERROR: four", "bye"]
    assert failure_message("deploy", 1, tail, job_id="J1") == (
        "`deploy` exited 1: ERROR: two / ERROR: three / ERROR: four"
        " Full output: boxmunge job show J1 --events.")


def test_failure_message_without_error_lines_uses_the_last_three() -> None:
    assert failure_message("deploy", 3, ["a", "b", "c", "d"], job_id="J1") == (
        "`deploy` exited 3: b / c / d Full output: boxmunge job show J1 --events.")


def test_failure_message_says_when_there_was_no_output() -> None:
    assert failure_message("deploy", 1, [], job_id="J1") == (
        "`deploy` exited 1: (no output) Full output: boxmunge job show J1 --events.")


def test_failure_message_is_capped() -> None:
    message = failure_message("deploy", 1, ["ERROR: " + "x" * 3000], job_id="J1")
    assert len(message) == 1000
    assert message.startswith("`deploy` exited 1: ERROR: xxx")
    assert message.endswith(" Full output: boxmunge job show J1 --events.")
