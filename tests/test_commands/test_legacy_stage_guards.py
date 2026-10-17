# SPDX-License-Identifier: Apache-2.0
"""legacy-stage's guards around the platform upgrade and the steps' edges:
upgrade.lock, an unreadable probation, errors a step can end in, staging
left without its compose files, and a linked .releases."""
from __future__ import annotations

import fcntl
import os
from unittest.mock import patch

import pytest

from boxmunge.commands.legacy_stage_cmd import run_legacy_stage
from boxmunge.legacy_stage import get_record, legacy_stage
from tests.bundle_helpers import tree_snapshot
from tests.test_commands.legacy_cmd_helpers import legacy_run


def _held_upgrade_lock(paths) -> int:
    paths.upgrade_state.mkdir(parents=True, exist_ok=True)
    fd = os.open(paths.upgrade_lock, os.O_WRONLY | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


@pytest.mark.parametrize("choice", ["discard", "keep-staged"])
def test_a_resolution_is_refused_while_an_upgrade_runs(paths, legacy, capsys, choice) -> None:
    """The shim holds upgrade.lock from before its stash to after the swap:
    a resolution in that window would be undone by a rollback's restore."""
    before = tree_snapshot(legacy)
    fd = _held_upgrade_lock(paths)
    try:
        assert run_legacy_stage(paths, "myapp", choice, False) == 1
    finally:
        os.close(fd)
    assert ("a platform upgrade is in progress; run it again after it finishes"
            in capsys.readouterr().err)
    assert tree_snapshot(legacy) == before and get_record(paths, "myapp") is None


def test_the_evidence_is_shown_while_an_upgrade_runs(paths, legacy, capsys) -> None:
    fd = _held_upgrade_lock(paths)
    try:
        with patch("boxmunge.docker_containers.created_times", return_value={}):
            assert run_legacy_stage(paths, "myapp", None, False) == 0
    finally:
        os.close(fd)
    assert "Choices:" in capsys.readouterr().out


def test_the_upgrade_lock_is_released_after_a_resolution(paths, legacy) -> None:
    from tests.stage_helpers import staging_docker_off
    with staging_docker_off(), \
            patch("boxmunge.legacy_stage_ops.compose_down"), \
            patch("boxmunge.legacy_stage_ops.caddy_reload"), \
            patch("boxmunge.legacy_stage_ops.notify"), \
            patch("boxmunge.legacy_stage.notify", return_value=True):
        assert run_legacy_stage(paths, "myapp", "discard", False) == 0
    os.close(_held_upgrade_lock(paths))


@pytest.mark.parametrize("probation", ["{not json", "[]", "{}"])
def test_an_unreadable_probation_refuses_with_its_fix(paths, legacy, capsys, probation) -> None:
    paths.probation.parent.mkdir(parents=True, exist_ok=True)
    paths.probation.write_text(probation)
    assert legacy_run(paths, "discard") == 1
    err = capsys.readouterr().err
    assert "cannot tell whether a platform rollback is possible" in err
    assert f"fix or remove {paths.probation}" in err and "Traceback" not in err
    assert legacy_stage(paths, "myapp") is not None


def test_an_unwritable_maintenance_page_says_run_it_again(paths, legacy, capsys) -> None:
    from boxmunge.commands.upgrade_steps import UpgradeGateError
    with patch("boxmunge.legacy_stage_ops.finish_apply",
               side_effect=UpgradeGateError("cannot write the maintenance page")):
        assert legacy_run(paths, "discard") == 1
    assert "cannot write the maintenance page. Run the same command again" in \
        capsys.readouterr().err


def test_a_refused_start_names_the_refusal_to_fix(paths, legacy, capsys) -> None:
    from boxmunge.compose_guard import ComposeRefused
    with patch("boxmunge.legacy_stage_ops.finish_apply",
               side_effect=ComposeRefused("mounts production's data")):
        assert legacy_run(paths, "discard") == 1
    err = capsys.readouterr().err
    assert "mounts production's data" in err and "Fix what it refuses, then run" in err


def test_staging_containers_without_their_compose_files_are_refused(
        paths, legacy, capsys, fake_containers) -> None:
    """0.10.1's teardown can unlink the overlay after a failed compose down."""
    for name in ("compose.boxmunge-staging.yml", "compose.staging-base.yml"):
        if os.path.lexists(legacy / name):
            (legacy / name).unlink()
    assert legacy_stage(paths, "myapp") is not None      # still a bundle stage
    fake_containers.run("myapp-staging", "app", "sha256:" + "a" * 64)
    assert legacy_run(paths, "discard") == 1
    err = capsys.readouterr().err
    assert "label=com.docker.compose.project=myapp-staging" in err and "docker rm -f" in err
    assert legacy_stage(paths, "myapp") is not None


def test_a_linked_releases_is_refused_before_the_stage_record_goes(paths, tmp_path,
                                                                  capsys) -> None:
    """A leftover reads no evidence, so step 6 is the first to reach .releases:
    it must not discard through a link there."""
    import shutil

    from boxmunge.commands.deploy import run_deploy
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle
    from tests.stage_helpers import V1
    from tests.txn_helpers import docker_off
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
    (paths.project_dir("myapp") / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "prestage.discarded").mkdir(parents=True)
    releases = paths.project_releases("myapp")
    shutil.rmtree(releases)
    releases.symlink_to(elsewhere)
    assert legacy_run(paths, "discard") == 1
    assert f"{releases} is not a directory" in capsys.readouterr().err
    assert (elsewhere / "prestage.discarded").is_dir()
