"""Operate cores never take the project lock ("One lock owner").

Every operate command is split into an entry point that takes the project
lock and a ``*_locked`` core that assumes it is held. A caller that already
holds the lock (promote composing deploy and unstage, the job worker of the
action API) runs cores directly. Here each core runs a real operation with
``project_lock`` replaced everywhere by a function that records the attempt
and raises, so a core reaching for the lock fails the test even if the
error is swallowed.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

import boxmunge.commands.backup_cmd as backup_cmd
import boxmunge.commands.deploy as deploy
import boxmunge.commands.pause_cmd as pause_cmd
import boxmunge.commands.project_delete_cmd as project_delete_cmd
import boxmunge.commands.promote_cmd as promote_cmd
import boxmunge.commands.recover_cmd as recover_cmd
import boxmunge.commands.restore as restore
import boxmunge.commands.resume_cmd as resume_cmd
import boxmunge.commands.rollback as rollback
import boxmunge.commands.security_resume as security_resume
import boxmunge.commands.security_scan_core as security_scan_core
import boxmunge.commands.stage_cmd as stage_cmd
import boxmunge.commands.unstage_cmd as unstage_cmd
import boxmunge.commands.upgrade_steps as upgrade_steps
import boxmunge.container_update as container_update
from boxmunge import fileutil
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.pause import is_paused, write_paused_state
from boxmunge.project_registry import add_project
from boxmunge.staged_release import load_slot
from boxmunge.state import write_state

from tests.bundle_helpers import place_bundle
from tests.test_commands.cve_helpers import make_box, scan_result, seed_quarantine
from tests.test_commands.test_restore_cmd import _setup_project
from tests.stage_helpers import V1, V2, staging_docker_off as _docker
from tests.test_lifecycle_locks import _cu_target, _setup

NAME = "myapp"


@pytest.fixture
def lock_attempts(monkeypatch) -> list[str]:
    """Replace project_lock in every loaded boxmunge module."""
    attempts: list[str] = []

    def forbidden(name, paths):
        attempts.append(name)
        raise AssertionError(f"an operate core took the project lock for {name!r}")

    real = fileutil.project_lock
    patched = []
    for module in list(sys.modules.values()):
        if (getattr(module, "__name__", "").startswith("boxmunge")
                and getattr(module, "project_lock", None) is real):
            patched.append(module.__name__)
            monkeypatch.setattr(module, "project_lock", forbidden)
    assert "boxmunge.commands.deploy" in patched and "boxmunge.fileutil" in patched
    yield attempts
    assert attempts == [], "a core acquired the project lock"


def _deployed_v1(paths) -> None:
    add_project(NAME, paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    with _docker():
        assert deploy.deploy_locked(NAME, paths, ref=V1) == 0


def _staged_v2(paths) -> None:
    _deployed_v1(paths)
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with _docker():
        assert stage_cmd.stage_locked(NAME, paths, ref=V2) == 0


def test_deploy_core(paths, lock_attempts) -> None:
    _deployed_v1(paths)


def test_stage_core(paths, lock_attempts) -> None:
    _staged_v2(paths)
    assert load_slot(paths, NAME).state == "ready"


@pytest.mark.xfail(strict=True, reason="Task 20: promote deploys the slot")
def test_promote_core(paths, lock_attempts) -> None:
    _staged_v2(paths)
    with _docker():
        assert promote_cmd.promote_locked(NAME, paths) == 0
    assert load_slot(paths, NAME) is None


def test_unstage_core(paths, lock_attempts) -> None:
    _staged_v2(paths)
    with _docker():
        assert unstage_cmd.unstage_locked(NAME, paths) == 0
    assert (paths.project_dir(NAME) / "VERSION").read_text() == "v1\n"
    assert load_slot(paths, NAME) is None


def test_rollback_core(paths, lock_attempts) -> None:
    _deployed_v1(paths)
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with _docker():
        assert deploy.deploy_locked(NAME, paths, ref=V2) == 0
        assert rollback.rollback_locked(NAME, paths) == 0
    assert (paths.project_dir(NAME) / "VERSION").read_text() == "v1\n"


def test_backup_core(paths, lock_attempts) -> None:
    _setup_project(paths)
    with patch.object(backup_cmd, "_run_backup_inner", return_value=0) as inner:
        assert backup_cmd.backup_locked(NAME, paths) == 0
    inner.assert_called_once()


def test_restore_core(paths, lock_attempts) -> None:
    _setup_project(paths)
    with patch.object(restore, "_run_restore_inner", return_value=0) as inner:
        assert restore.restore_locked(NAME, paths, None) == 0
    inner.assert_called_once()


def test_pause_core(tmp_path, lock_attempts) -> None:
    paths = _setup(tmp_path)
    with patch.object(pause_cmd, "caddy_reload"), patch.object(pause_cmd, "compose_stop"), \
            patch.object(pause_cmd, "hold_restart_policies"):
        assert pause_cmd.pause_locked(NAME, paths, None) == 0
    assert is_paused(NAME, paths)


def test_resume_core(tmp_path, lock_attempts) -> None:
    paths = _setup(tmp_path)
    write_paused_state(NAME, paths)
    with patch.object(resume_cmd, "compose_pull"), \
            patch("boxmunge.compose_guard.compose_up"), \
            patch.object(resume_cmd, "caddy_reload"), \
            patch.object(resume_cmd, "prepare_caddy_config"), \
            patch.object(resume_cmd, "prepare_compose_override"), \
            patch.object(resume_cmd, "release_restart_policies"), \
            patch.object(resume_cmd, "run_smoke", return_value=(True, "")):
        assert resume_cmd.resume_locked(NAME, paths, False) == (0, None)
    assert not is_paused(NAME, paths)


def test_recover_core(tmp_path, lock_attempts) -> None:
    paths = _setup(tmp_path)
    write_state(paths.project_health_state(NAME), {"status": "critical_stopped"})
    with patch("boxmunge.compose_guard.compose_up"), patch.object(recover_cmd, "caddy_reload"), \
            patch.object(recover_cmd, "prepare_caddy_config"), \
            patch.object(recover_cmd, "prepare_compose_override"), \
            patch.object(recover_cmd, "run_smoke", return_value=(True, "")):
        assert recover_cmd.recover_locked(NAME, paths) == 0


def test_project_delete_core(tmp_path, lock_attempts) -> None:
    paths = _setup(tmp_path)
    with patch.object(project_delete_cmd, "compose_down"), \
            patch.object(project_delete_cmd, "caddy_reload"):
        assert project_delete_cmd.delete_locked(NAME, paths, force=False) == 0
    assert not paths.project_dir(NAME).exists()


def test_security_resume_core(tmp_path, monkeypatch, lock_attempts) -> None:
    paths = make_box(tmp_path, services=("web",))
    seed_quarantine(paths)
    monkeypatch.setattr(security_scan_core, "scan_image", lambda ref, timeout: scan_result(ref))
    monkeypatch.setattr(security_resume, "prepare_caddy_config", lambda p, m: None)
    monkeypatch.setattr(security_resume, "prepare_compose_override",
                        lambda p, m, component=None: None)
    monkeypatch.setattr(security_resume, "run_smoke", lambda p, paths_: (True, "ok"))
    lifted = MagicMock()
    monkeypatch.setattr(security_resume, "lift_quarantine", lifted)
    assert security_resume.security_resume_locked(paths, "demo") == 0
    lifted.assert_called_once()
    assert is_quarantined("demo", paths)  # the stubbed lift clears nothing


def test_container_update_core(tmp_path, lock_attempts) -> None:
    paths = _setup(tmp_path)
    with patch.object(container_update, "backup_locked", return_value=0), \
            patch.object(container_update, "compose_pull"), \
            patch("boxmunge.compose_guard.compose_up") as up, \
            patch.object(container_update, "_wait_healthy", return_value=(True, [])), \
            patch.object(container_update, "detect_image_changes",
                         return_value={"web": "sha256:new"}):
        result = container_update._update_locked(
            paths, _cu_target(paths, has_backup=True), {
                "name": NAME, "ts": "2026-10-16T00:00:00+00:00", "status": "succeeded", "rollback_attempted": False,
                "rollback_succeeded": None, "previous_digests": {},
                "current_digests": {}, "reason": None,
            })
    assert result["status"] == "succeeded"
    up.assert_called_once()


def test_upgrade_restart_core(tmp_path, lock_attempts) -> None:
    paths = _setup(tmp_path)
    result = upgrade_steps.Restart()
    with patch("boxmunge.compose_guard.compose_up") as up:
        upgrade_steps._restart_locked(paths, paths.project_dir(NAME), NAME, (), result)
    up.assert_called_once()
    assert result.succeeded == [NAME]
