"""A pause that fails part-way says so, and pausing again finishes it.

The pause record is written first, so automation leaves the project alone
from the start, but it is marked complete only once the maintenance page
is live, the containers are stopped and their restart policies held.
"""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands import pause_cmd
from boxmunge.docker import DockerError
from boxmunge.pause import is_paused, pause_action_complete, read_paused_state

from tests.test_lifecycle_locks import NAME, _setup


def _pause(paths, *, reload_error=None, stop_error=None, hold_error=None) -> int:
    with patch.object(pause_cmd, "caddy_reload", side_effect=reload_error), \
            patch.object(pause_cmd, "compose_stop", side_effect=stop_error) as stop, \
            patch.object(pause_cmd, "hold_restart_policies", side_effect=hold_error):
        rc = pause_cmd.run_pause(NAME, paths, yes=True, reason="maintenance")
    _pause.stop_calls = stop.call_count
    return rc


def test_failed_stop_is_reported_and_recorded_as_incomplete(tmp_path, capsys) -> None:
    paths = _setup(tmp_path)
    assert _pause(paths, stop_error=DockerError("daemon not responding")) == 1
    err = capsys.readouterr().err
    assert "incomplete" in err and f"pause {NAME}' again" in err
    assert is_paused(NAME, paths)
    assert not pause_action_complete(NAME, paths)


def test_failed_caddy_swap_is_recorded_as_incomplete(tmp_path) -> None:
    paths = _setup(tmp_path)
    assert _pause(paths, reload_error=DockerError("caddy down")) == 1
    assert _pause.stop_calls == 0, "containers must not stop before the page is live"
    assert is_paused(NAME, paths)
    assert not pause_action_complete(NAME, paths)


def test_pausing_again_finishes_an_incomplete_pause(tmp_path) -> None:
    paths = _setup(tmp_path)
    assert _pause(paths, stop_error=DockerError("daemon not responding")) == 1
    paused_at = read_paused_state(NAME, paths)["paused_at"]
    assert _pause(paths) == 0
    assert _pause.stop_calls == 1
    assert pause_action_complete(NAME, paths)
    state = read_paused_state(NAME, paths)
    assert state["paused_at"] == paused_at and state["reason"] == "maintenance"


def test_a_complete_pause_refuses_to_pause_again(tmp_path, capsys) -> None:
    paths = _setup(tmp_path)
    assert _pause(paths) == 0
    assert pause_action_complete(NAME, paths)
    assert _pause(paths) == 1
    assert _pause.stop_calls == 0
    assert "already paused" in capsys.readouterr().err
