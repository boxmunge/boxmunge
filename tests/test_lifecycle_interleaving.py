"""A pause or quarantine that completes while a command waits for the
project lock wins (codebase review finding 07).

Each test inserts a real pause or quarantine marker at the exact moment the
command acquires the project lock: the marker is written, then the real
flock is taken. That is the interleaving a concurrent pause/quarantine
produces when it finishes and releases its lock just before the waiting
command gets it. Nothing may restart or change afterwards.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from boxmunge import fileutil
from boxmunge.commands import (
    backup_cmd, check, deploy, promote_cmd, restore, rollback, stage_cmd, upgrade_steps,
)
from boxmunge.pause import write_paused_state
from boxmunge.project_registry import add_project
from boxmunge.staged_release import load_slot
from boxmunge.state import write_state

from tests.bundle_helpers import place_bundle
from tests.test_commands.test_restore_cmd import _setup_project
from tests.stage_helpers import V1, V2, prod_and_stage, staging_docker_off as _docker

NAME = "myapp"


def _quarantine(name, paths):
    write_state(paths.project_quarantine_state(name), {"cve_id": "CVE-2099-0001"})


def _pause(name, paths):
    write_paused_state(name, paths)


MARKERS = pytest.mark.parametrize("marker", [_quarantine, _pause], ids=["quarantine", "pause"])


@contextmanager
def _marker_at_lock(module, marker):
    """Patch ``module.project_lock``: write the marker, then take the real lock."""
    @contextmanager
    def lock(name, paths):
        marker(name, paths)
        with fileutil.project_lock(name, paths):
            yield
    with patch.object(module, "project_lock", lock):
        yield


def _version(paths) -> str:
    return (paths.project_dir(NAME) / "VERSION").read_text()


@MARKERS
def test_deploy_never_starts_once_blocked(paths, marker) -> None:
    add_project(NAME, paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    with _docker():
        assert deploy.run_deploy(NAME, paths, ref=V1) == 0
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with _docker(), patch("boxmunge.compose_guard.compose_up") as up, \
            _marker_at_lock(deploy, marker):
        assert deploy.run_deploy(NAME, paths, ref=V2) == 1
    up.assert_not_called()
    assert _version(paths) == "v1\n"


@MARKERS
def test_stage_never_starts_once_blocked(paths, marker) -> None:
    add_project(NAME, paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    with _docker():
        assert deploy.run_deploy(NAME, paths, ref=V1) == 0
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with _docker(), patch("boxmunge.compose_guard.compose_up") as up, \
            _marker_at_lock(stage_cmd, marker):
        assert stage_cmd.run_stage(NAME, paths, ref=V2) == 1
    up.assert_not_called()
    assert load_slot(paths, NAME) is None
    assert _version(paths) == "v1\n"


@MARKERS
def test_promote_never_starts_once_blocked(paths, marker) -> None:
    prod_and_stage(paths)
    with _docker(), patch("boxmunge.compose_guard.compose_up") as up, \
            _marker_at_lock(promote_cmd, marker):
        assert promote_cmd.run_promote(NAME, paths) == 1
    up.assert_not_called()
    assert load_slot(paths, NAME).state == "ready"


@MARKERS
def test_rollback_never_starts_once_blocked(paths, marker) -> None:
    add_project(NAME, paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with _docker():
        assert deploy.run_deploy(NAME, paths, ref=V1) == 0
        assert deploy.run_deploy(NAME, paths, ref=V2) == 0
    with _docker(), patch("boxmunge.compose_guard.compose_up") as up, \
            _marker_at_lock(rollback, marker):
        assert rollback.run_rollback(NAME, paths, yes=True) == 1
    up.assert_not_called()
    assert _version(paths) == "v2\n"


@MARKERS
def test_restore_never_touches_production_once_blocked(paths, marker) -> None:
    _setup_project(paths)
    with patch.object(restore, "_run_restore_inner") as inner, \
            _marker_at_lock(restore, marker):
        assert restore.run_restore(NAME, paths, yes=True) == 1
    inner.assert_not_called()


@MARKERS
def test_backup_never_dumps_once_blocked(paths, marker) -> None:
    _setup_project(paths)
    with patch.object(backup_cmd, "_run_backup_inner") as inner, \
            _marker_at_lock(backup_cmd, marker):
        backup_cmd.run_backup(NAME, paths)
    inner.assert_not_called()


def _deployed(paths) -> None:
    pdir = paths.project_dir(NAME)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(f"project: {NAME}\nhosts: [{NAME}.example.com]\n")
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")


@MARKERS
def test_upgrade_restart_never_starts_once_blocked(paths, marker) -> None:
    """The upgrade restart recorded success with the marker present."""
    _deployed(paths)
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch.object(upgrade_steps, "_addressable", return_value=True), \
            _marker_at_lock(upgrade_steps, marker):
        result = upgrade_steps.restart_projects(paths, refused=())
    up.assert_not_called()
    assert result == upgrade_steps.Restart()


@MARKERS
def test_health_tick_never_checks_once_blocked(paths, marker) -> None:
    """A smoke run against a just-paused project would escalate and stop it."""
    _deployed(paths)
    run_check = MagicMock()
    with patch.object(check, "run_check", run_check), _marker_at_lock(check, marker):
        assert check._check_project(NAME, paths, read_only=False) == 0
    run_check.assert_not_called()


@MARKERS
def test_container_update_never_recreates_once_blocked(tmp_path, marker) -> None:
    from boxmunge.commands import container_update_cmd
    from tests.test_lifecycle_locks import _cu_target, _setup
    paths = _setup(tmp_path)
    with patch.object(container_update_cmd, "update_target_locked") as update, \
            patch.object(container_update_cmd, "_dry_run_target",
                         return_value={"status": "no_change"}), \
            _marker_at_lock(container_update_cmd, marker):
        result = container_update_cmd.update_project(paths, _cu_target(paths), dry_run=False)
    update.assert_not_called()
    assert result["status"] in ("quarantined", "paused")
