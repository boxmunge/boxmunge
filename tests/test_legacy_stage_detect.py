"""A stage left by boxmunge 0.10.1 is detected and every touch is refused."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from boxmunge.compose_guard import ComposeRefused, compose_up_checked
from boxmunge.legacy_stage import legacy_stage, legacy_staging_state, refuse_if_legacy_stage
from tests.stage_helpers import prod_and_stage

P = "myapp"


def _state(paths, active=True, ref=None):
    path = legacy_staging_state(paths, P)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"active": active, "ref": ref}))


@pytest.mark.parametrize("setup,kind", [
    (lambda pdir, paths: (pdir / ".releases" / "prestage" / "release").mkdir(parents=True), "bundle"),
    (lambda pdir, paths: ((pdir / "repo").mkdir(), _state(paths)), "git"),
    (lambda pdir, paths: ((pdir / "repo").mkdir(), (pdir / "compose.boxmunge-staging.yml").write_text("")), "git"),
    (lambda pdir, paths: _state(paths), "leftover"),
    (lambda pdir, paths: (pdir / "compose.staging-base.yml").write_text(""), "leftover"),
])
def test_kinds(paths, setup, kind) -> None:
    pdir = paths.project_dir(P)
    pdir.mkdir(parents=True)
    setup(pdir, paths)
    assert legacy_stage(paths, P).kind == kind


def test_inactive_state_and_no_files_is_not_a_stage(paths) -> None:
    paths.project_dir(P).mkdir(parents=True)
    _state(paths, active=False)
    assert legacy_stage(paths, P) is None


@pytest.mark.parametrize("text", ["{not json", "[]", "null"])
def test_unreadable_state_counts_as_a_stage(paths, text) -> None:
    """Fail-safe: a state file that cannot be read as 0.10.1 wrote it may
    record an active stage, so the project is refused until legacy-stage
    has looked at the evidence."""
    paths.project_dir(P).mkdir(parents=True)
    path = legacy_staging_state(paths, P)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    assert legacy_stage(paths, P).kind == "leftover"


def test_new_layout_stage_is_not_legacy(paths) -> None:
    prod_and_stage(paths)
    assert legacy_stage(paths, P) is None


def test_production_starts_and_commands_refused(paths, capsys) -> None:
    prod_and_stage(paths)
    (paths.project_releases(P) / "prestage").mkdir()
    with patch("boxmunge.compose_guard.compose_up") as up, pytest.raises(ComposeRefused,
                                                                         match="legacy-stage"):
        compose_up_checked(paths, P, component="upgrade",
                           compose_files=["compose.yml", "compose.boxmunge.yml"])
    up.assert_not_called()
    assert refuse_if_legacy_stage(paths, P) is True
    assert f"boxmunge-server legacy-stage {P}" in capsys.readouterr().err


def test_container_starts_refused(paths) -> None:
    """A `docker start` of production's stopped containers (data adopt, the
    staging copy's start-again) is a production start too."""
    from boxmunge.compose_guard import start_containers_checked
    prod_and_stage(paths)
    (paths.project_releases(P) / "prestage").mkdir()
    with patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.docker_containers.container_bind_sources", return_value=[]), \
            pytest.raises(ComposeRefused, match="legacy-stage"):
        start_containers_checked(paths, P, [f"{P}-web-1"], component="data-adopt")
    start.assert_not_called()


def test_data_adopt_refuses_before_touching_docker(paths) -> None:
    from boxmunge.commands import data_cmd
    prod_and_stage(paths)
    (paths.project_releases(P) / "prestage").mkdir()
    with patch.object(data_cmd, "_run") as run, \
            patch.object(data_cmd, "container_mounts") as mounts, \
            pytest.raises(data_cmd.DataError, match="legacy-stage"):
        data_cmd.adopt_locked(paths, P, "web", "/data", "data")
    run.assert_not_called()
    mounts.assert_not_called()


def test_new_layout_stage_does_not_refuse_production_starts(paths) -> None:
    prod_and_stage(paths)
    with patch("boxmunge.compose_guard.compose_up") as up:
        compose_up_checked(paths, P, component="upgrade", compose_files=["compose.yml"])
    up.assert_called_once()
    assert refuse_if_legacy_stage(paths, P) is False


def _cores():
    from boxmunge.commands.deploy import deploy_locked
    from boxmunge.commands.promote_cmd import promote_locked
    from boxmunge.commands.recover_cmd import recover_locked
    from boxmunge.commands.resume_cmd import resume_locked
    from boxmunge.commands.rollback import rollback_locked
    from boxmunge.commands.stage_cmd import stage_locked
    from boxmunge.commands.unstage_cmd import unstage_locked
    return {
        "stage": lambda paths: stage_locked(P, paths),
        "unstage": lambda paths: unstage_locked(P, paths),
        "promote": lambda paths: promote_locked(P, paths),
        "prod-deploy": lambda paths: deploy_locked(P, paths),
        "rollback": lambda paths: rollback_locked(P, paths),
        "resume": lambda paths: resume_locked(P, paths, False)[0],
        "recover": lambda paths: recover_locked(P, paths),
    }


@pytest.mark.parametrize("name", ["stage", "unstage", "promote", "prod-deploy", "rollback",
                                  "resume", "recover"])
def test_every_core_refuses(paths, name, capsys) -> None:
    prod_and_stage(paths)
    (paths.project_releases(P) / "prestage").mkdir()
    assert _cores()[name](paths) == 1
    assert "legacy-stage" in capsys.readouterr().err


def test_deploy_eligible_refuses(paths, capsys) -> None:
    from boxmunge.commands.deploy import deploy_eligible
    prod_and_stage(paths)
    (paths.project_releases(P) / "prestage").mkdir()
    assert deploy_eligible(P, paths) is False
    assert "legacy-stage" in capsys.readouterr().err


def test_restore_and_pause_refuse(paths, capsys) -> None:
    from boxmunge.commands.pause_cmd import pause_locked
    from boxmunge.commands.restore import restore_locked
    prod_and_stage(paths)
    (paths.project_releases(P) / "prestage").mkdir()
    assert restore_locked(P, paths, snapshot=None) == 1
    assert pause_locked(P, paths, reason=None) == 1
    assert capsys.readouterr().err.count("legacy-stage") >= 2


def test_unstage_refuses_a_legacy_stage_without_a_slot(paths, capsys) -> None:
    """With nothing in the slot, unstage names legacy-stage rather than
    saying no staging was found."""
    from boxmunge.commands.unstage_cmd import unstage_locked
    paths.project_dir(P).mkdir(parents=True)
    _state(paths)
    assert unstage_locked(P, paths) == 1
    assert "legacy-stage" in capsys.readouterr().err
