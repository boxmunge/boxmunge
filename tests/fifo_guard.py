"""Run a read that must not block on a planted FIFO, with a time limit."""
from __future__ import annotations

import os
import threading
from collections.abc import Callable
from pathlib import Path

import pytest


def raised_without_blocking(fn: Callable[[], object], fifo: Path,
                            timeout: float = 5.0) -> BaseException:
    """Run ``fn`` in a thread and return what it raised. A call still
    blocked after ``timeout`` (opening ``fifo`` waits for a writer) is
    released by opening the FIFO for writing, and fails the test."""
    outcome: dict[str, object] = {}

    def run() -> None:
        try:
            outcome["value"] = fn()
        except BaseException as e:  # noqa: BLE001 - handed back to the test
            outcome["error"] = e

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        thread.join(timeout)
        pytest.fail(f"reading {fifo} blocked on the FIFO")
    if "error" not in outcome:
        pytest.fail(f"reading {fifo} returned {outcome.get('value')!r} instead of refusing")
    return outcome["error"]  # type: ignore[return-value]
