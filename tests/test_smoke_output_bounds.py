# SPDX-License-Identifier: Apache-2.0
"""A smoke's output is drained, bounded and decoded with replacement, with real
processes and pipes: invalid bytes never take the exit status away, and a
command that floods a stream cannot make the host hold it."""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import service_exec
from boxmunge import bounded_run
from boxmunge.bounded_run import OutputBudgetExceeded, OutputNotClosed, run_bounded
from boxmunge.commands import check
from boxmunge.service_exec import Stop

SH = ["sh", "-c"]


def _run(script: str, **kw):
    return run_bounded([*SH, script], timeout=30, keep=kw.pop("keep", 1000),
                       budget=kw.pop("budget", 10**8), **kw)


@pytest.mark.parametrize("code", [0, 1, 2])
def test_invalid_utf8_on_either_stream_keeps_the_exit_status(code: int) -> None:
    r = _run(f"printf 'ok\\377\\n'; printf 'bad\\377\\n' >&2; exit {code}",
             capture_output=True, text=True)
    assert r.returncode == code
    assert r.stdout == "ok�\n" and r.stderr == "bad�\n"


def test_floods_on_both_streams_are_drained_and_only_the_head_kept() -> None:
    # 4 MiB on each stream: more than a pipe holds, so an undrained one deadlocks.
    r = _run("head -c 4194304 /dev/zero | tr '\\0' o; head -c 4194304 /dev/zero | tr '\\0' e >&2; exit 2",
             capture_output=True, text=True, keep=500)
    assert r.returncode == 2
    assert r.stdout == "o" * 500 and r.stderr == "e" * 500


def test_a_stream_past_its_budget_kills_the_command() -> None:
    with pytest.raises(OutputBudgetExceeded) as e:
        _run("head -c 4194304 /dev/zero >&2; sleep 30", capture_output=True, budget=1 << 20)
    assert e.value.stream == "stderr"


def test_a_plain_timeout_kills_and_raises() -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded([*SH, "sleep 30"], timeout=0.5, keep=10, budget=100, capture_output=True)


def test_a_grandchild_holding_the_pipe_fails_noisily_instead_of_hanging(monkeypatch) -> None:
    monkeypatch.setattr(bounded_run, "DRAIN_GRACE", 0.5)
    with pytest.raises(OutputNotClosed) as e:
        _run("sleep 5 & exit 2", capture_output=True)
    assert "left stdout open" in e.value.reason


def test_a_drain_that_fails_is_raised(monkeypatch) -> None:
    monkeypatch.setattr(bounded_run, "_CHUNK", "not a size")  # the read raises in the thread
    with pytest.raises(TypeError):
        _run("echo hi", capture_output=True)


def test_text_translates_newlines_as_text_mode_did() -> None:
    assert _run("printf 'a\\r\\nb\\rc'", capture_output=True, text=True).stdout == "a\nb\nc"


def test_a_stream_that_is_not_captured_is_not_bounded(tmp_path: Path) -> None:
    out = tmp_path / "dump"
    with out.open("wb") as f:
        r = _run("head -c 3000000 /dev/zero; echo err >&2", stdout=f, stderr=subprocess.PIPE,
                 budget=1000)
    assert out.stat().st_size == 3000000 and r.stderr == b"err\n" and r.stdout is None


def _smoke(tmp_path: Path, body: str, **limits: int) -> check.SmokeResult:
    """check._smoke_one against a real script, run by the real wrapper in
    this host in place of a container; stopping it is recorded."""
    script = tmp_path / "smoke.sh"
    script.write_text(body)

    def local(container, command, *, timeout, env, **kw):
        return service_exec._run([], "here", command, timeout=timeout, **kw)

    stops: list[str] = []

    def stop(exec_into, pid_name, cwd=None):
        stops.append(pid_name)
        return Stop("4242", None)

    with patch.object(check, "run_in_container", local), \
         patch.object(service_exec, "_stop", stop), \
         patch.multiple(service_exec, **{"OUTPUT_KEEP": 10**5, "OUTPUT_BUDGET": 10**8,
                                      **{k.upper(): v for k, v in limits.items()}}):
        result = check._smoke_one("c", str(script), "web")
    result.stops = stops  # type: ignore[attr-defined]
    return result


@pytest.mark.parametrize("code,status", [(0, "ok"), (1, "warning"), (2, "critical")])
def test_a_smoke_with_invalid_bytes_on_both_streams_still_has_its_verdict(
        tmp_path: Path, code: int, status: str) -> None:
    r = _smoke(tmp_path, f"printf 'x\\377\\n'; printf 'cannot open \\377\\n' >&2; exit {code}")
    assert r.status == status
    if code:
        assert "cannot open �" in r.message
    assert r.stops == []  # nothing was left to stop


def test_a_critical_verdict_survives_a_truncated_message(tmp_path: Path) -> None:
    r = _smoke(tmp_path, "head -c 3000000 /dev/zero | tr '\\0' m >&2; exit 2",
               output_keep=200)
    assert r.status == "critical" and r.message == "m" * 200


def test_a_smoke_flooding_past_the_budget_is_stopped_in_its_container_and_says_why(
        tmp_path: Path) -> None:
    r = _smoke(tmp_path, "head -c 4000000 /dev/zero | tr '\\0' o; exit 2",
               output_budget=1 << 20)
    assert r.status == "warning"  # a smoke that did not finish has no verdict
    assert "wrote more than 1048576 bytes on stdout" in r.message
    assert "stopped there" in r.message
    assert len(r.stops) == 1  # the in-container stop ran once
