"""`resume` is the pause's exit, so it must also be the repair for what a
pause can be left holding (logic review 2026-11-09, findings 01 and 02).

A deploy is refused while a project is paused, so a resume that answered
"redeploy" would leave no way out but deleting the pause record by hand.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands.resume_cmd import run_resume
from boxmunge.pause import is_paused, read_paused_state
from tests.test_commands.test_resume_cmd import _setup_paused


@pytest.fixture
def started():
    """Resume's surroundings stood in for; yields the `compose up` mock."""
    with patch("boxmunge.commands.resume_cmd.prepare_compose_override"), \
            patch("boxmunge.commands.resume_cmd.prepare_caddy_config"), \
            patch("boxmunge.commands.resume_cmd.caddy_reload"), \
            patch("boxmunge.commands.resume_cmd.run_smoke", return_value=(True, "ok")), \
            patch("boxmunge.compose_guard.compose_up") as up:
        yield up


def _pre_rule_containers(monkeypatch, paths, name) -> None:
    """Its stopped containers were created before the own-file rules: they
    mount the project directory read-write (0.10.x accepted `.:/app`)."""
    existing = [(str(paths.project_dir(name)), True)]
    monkeypatch.setattr("boxmunge.docker_containers.container_bind_sources",
                        lambda project: existing)


def test_pre_rule_containers_are_recreated_from_the_checked_files(
        tmp_path, monkeypatch, started, capsys) -> None:
    paths, name = _setup_paused(tmp_path)
    _pre_rule_containers(monkeypatch, paths, name)
    assert run_resume(name, paths, yes=True, skip_security_checks=True) == 0
    started.assert_called_once()
    assert started.call_args.kwargs["force_recreate"] is True
    assert not is_paused(name, paths)
    out = capsys.readouterr().out
    assert "mounts the project directory read-write" in out and "Recreating them" in out


def test_containers_that_pass_are_started_not_recreated(tmp_path, started) -> None:
    paths, name = _setup_paused(tmp_path)
    assert run_resume(name, paths, yes=True, skip_security_checks=True) == 0
    assert started.call_args.kwargs["force_recreate"] is False


def test_only_the_container_check_is_lifted(tmp_path, monkeypatch, started) -> None:
    """A control file changed since the deploy is still refused: the recreate
    runs only files the deploy validated and recorded."""
    paths, name = _setup_paused(tmp_path)
    _pre_rule_containers(monkeypatch, paths, name)
    (paths.project_dir(name) / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.27\n")
    assert run_resume(name, paths, yes=True, skip_security_checks=True) == 3
    started.assert_not_called()
    assert is_paused(name, paths)
