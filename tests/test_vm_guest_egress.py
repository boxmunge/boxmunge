# SPDX-License-Identifier: Apache-2.0
"""The VM harness's guest network probe retries each host check before
declaring it unreachable: one slow CDN answer must not abort a run."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "vm"))
import vm_guest_access as vga  # noqa: E402


def _result(code: int) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], code, "", "timed out" if code else "")


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    slept: list[float] = []
    monkeypatch.setattr(vga.time, "sleep", slept.append)
    return slept


def test_a_host_that_fails_once_then_answers_is_reachable(sleeps) -> None:
    calls: list[str] = []

    def ssh_run(user, port, command, check=True):
        calls.append(command)
        # alpine's CDN: slow over the default (IPv6) path, fast over IPv4
        slow = "dl-cdn.alpinelinux.org" in command and " -4 " not in command
        return _result(28 if slow else 0)

    vga.check_guest_egress(ssh_run, 1)
    alpine = [c for c in calls if "dl-cdn.alpinelinux.org" in c]
    assert len(alpine) == 2 and " -4 " in alpine[1]
    assert sleeps == [5]


def test_a_host_that_never_answers_fails_after_three_attempts(sleeps) -> None:
    calls: list[str] = []

    def ssh_run(user, port, command, check=True):
        calls.append(command)
        return _result(28 if "github.com/" in command else 0)

    with pytest.raises(RuntimeError, match=r"(?s)cannot reach every host.*github\.com"):
        vga.check_guest_egress(ssh_run, 1)
    assert len([c for c in calls if "https://github.com/" in c]) == 3
    assert sleeps == [5, 10]
