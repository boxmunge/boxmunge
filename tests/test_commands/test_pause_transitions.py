"""A pause that fails part-way says so, and pausing again finishes it.

The pause record is written first, so automation leaves the project alone
from the start, but it is marked complete only once the maintenance page
is live, the containers are stopped and their restart policies held.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

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


# ---- an install that has not finished (logic review 2026-11-09, finding 02) ----

_KEEP = ("committed", "previous_kept", "installed", "hook_started", "switching")


def _open_install(paths, phase: str):
    """A deploy of v2 over v1 left open at `phase` (bundle source)."""
    from boxmunge.release import mark_live
    from boxmunge.release_txn import advance, open_txn
    mark_live(paths, NAME, f"{NAME}-v1")
    txn = open_txn(paths, NAME, source="bundle", ref=f"{NAME}-v2",
                   replaced_ref=f"{NAME}-v1", staged_id=None, snapshot="")
    for step in _KEEP[1:_KEEP.index(phase) + 1]:
        txn = advance(paths, NAME, txn, step)
    return txn


@pytest.mark.parametrize("phase", _KEEP)
def test_pause_is_refused_while_an_install_is_open(tmp_path, capsys, phase) -> None:
    """Every way out of an open install is a deploy, a rollback or an
    abandon; a pause would refuse the first two and make resume wait for the
    install, and its stop would run the new release's compose model over
    the old release's containers. So nothing of the pause happens, and the
    refusal names the install's own options."""
    paths = _setup(tmp_path)
    _open_install(paths, phase)
    site = paths.project_caddy_site(NAME).read_text()
    assert _pause(paths) == 1
    assert _pause.stop_calls == 0 and not is_paused(NAME, paths)
    assert paths.project_caddy_site(NAME).read_text() == site
    err = capsys.readouterr().err
    assert f"an install of {NAME}-v2 (bundle) is open at phase {phase}" in err
    assert f"prod-deploy {NAME} --ref {NAME}-v2" in err


def test_a_paused_project_refuses_to_pause_again_naming_resume(tmp_path, capsys) -> None:
    paths = _setup(tmp_path)
    assert _pause(paths) == 0
    assert _pause(paths) == 1
    assert f"resume {NAME}" in capsys.readouterr().err


@pytest.mark.parametrize("phase", ["installed", "hook_started", "switching"])
def test_a_pause_taken_over_an_open_install_is_handed_to_it(tmp_path, capsys, phase) -> None:
    """Paused over an open install by an earlier boxmunge: the install's
    options are deploys, refused while it is paused, and nothing may start
    production but the install. Resume refuses, naming `--no-start`, which
    hands the pause to the install's deploy without starting anything."""
    from boxmunge.commands.deploy import deploy_eligible
    from boxmunge.commands.resume_cmd import hand_to_deploy_locked, resume_locked
    from boxmunge.pause import awaiting_deploy, mark_pause_complete, write_paused_state
    paths = _setup(tmp_path)
    _open_install(paths, phase)
    write_paused_state(NAME, paths, reason="maintenance")
    mark_pause_complete(NAME, paths)
    site = paths.project_caddy_site(NAME).read_text()
    with patch("boxmunge.compose_guard.compose_up") as up:
        assert resume_locked(NAME, paths, skip_security_checks=True) == (1, None)
        err = capsys.readouterr().err
        assert f"resume {NAME} --no-start" in err
        assert not deploy_eligible(NAME, paths)
        assert hand_to_deploy_locked(NAME, paths) == 0
    up.assert_not_called()
    assert is_paused(NAME, paths) and awaiting_deploy(NAME, paths)
    assert paths.project_caddy_site(NAME).read_text() == site   # the page stays up
    assert f"prod-deploy {NAME} --ref {NAME}-v2" in capsys.readouterr().out
    assert deploy_eligible(NAME, paths)
