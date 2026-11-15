# SPDX-License-Identifier: Apache-2.0
"""fd-level output capture, the output tail, and the core-failure message."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from boxmunge.api.job_capture import (
    CAPTURE_DRAIN_SECONDS, OUTPUT_TAIL_LINES, CoreFailed, OutputTail, capture_output,
    failure_message,
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
