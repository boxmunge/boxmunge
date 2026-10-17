# SPDX-License-Identifier: Apache-2.0
"""A crash after each step of a resolution is finished by running the same
command again, and a rerun can only finish the choice that was started."""
from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from boxmunge.commands.rollback import find_rollback_target
from boxmunge.legacy_stage import get_record, legacy_stage, legacy_staging_state
from boxmunge.state import read_state
from tests.git_helpers import git
from tests.stage_helpers import V1, V2
from tests.test_commands.legacy_cmd_helpers import legacy_run

STEPS = ["_stop_legacy_staging", "_remove_staging_site", "_production_code", "_clean_up",
         "drop_stage_record", "finish_apply"]


@pytest.mark.parametrize("choice", ["discard", "keep-staged"])
@pytest.mark.parametrize("step", STEPS)
def test_a_crashed_git_resolution_is_finished_by_the_same_command(paths, legacy_git,
                                                                 choice, step) -> None:
    from tests.txn_helpers import fake_backups
    a, b, repo, t = legacy_git
    taken: list[dict] = []
    with fake_backups(taken):
        with patch(f"boxmunge.legacy_stage_ops.{step}", side_effect=OSError("crash")):
            assert legacy_run(paths, choice, at=t, created=(-1,)) == 1
        assert legacy_run(paths, choice, at=t, created=(-1,)) == 0
    assert git("rev-parse", "HEAD", cwd=repo) == (a if choice == "discard" else b)
    assert legacy_stage(paths, "myapp") is None and get_record(paths, "myapp") is None
    if choice == "keep-staged":
        assert len(taken) == 1   # one snapshot, however many runs
        assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == b


@pytest.mark.parametrize("step", STEPS)
def test_a_crashed_never_deployed_keep_staged_is_finished(paths, never_deployed, step) -> None:
    pdir = never_deployed
    with patch("boxmunge.commands.backup_cmd.backup_locked",
               side_effect=AssertionError("nothing was deployed to snapshot")):
        with patch(f"boxmunge.legacy_stage_ops.{step}", side_effect=OSError("crash")):
            assert legacy_run(paths, "keep-staged") == 1
        assert legacy_run(paths, "keep-staged") == 0
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == f"myapp-{V2}"
    assert legacy_stage(paths, "myapp") is None and get_record(paths, "myapp") is None



def test_a_different_choice_on_rerun_is_refused(paths, legacy, capsys) -> None:
    with patch("boxmunge.legacy_stage_ops._production_code", side_effect=OSError("crash")):
        assert legacy_run(paths, "discard") == 1
    assert legacy_run(paths, "keep-staged") == 1
    assert "--discard" in capsys.readouterr().err
    assert legacy_run(paths, "discard") == 0


@pytest.mark.parametrize("step", ["_stop_legacy_staging", "_remove_staging_site",
                                  "_production_code", "_clean_up", "drop_stage_record",
                                  "finish_apply"])
def test_a_crash_after_each_step_is_finished_by_the_same_command(paths, legacy, step) -> None:
    with patch(f"boxmunge.legacy_stage_ops.{step}", side_effect=OSError("crash")):
        assert legacy_run(paths, "discard") == 1
    assert legacy_run(paths, "discard") == 0
    assert (legacy / "VERSION").read_text() == "v1\n" and get_record(paths, "myapp") is None


@pytest.mark.parametrize("step", ["_production_code", "_clean_up", "drop_stage_record",
                                  "finish_apply"])
def test_a_crash_during_keep_staged_is_finished_by_the_same_command(paths, legacy,
                                                                   step) -> None:
    from tests.txn_helpers import fake_backups
    taken: list[dict] = []
    with fake_backups(taken):
        with patch(f"boxmunge.legacy_stage_ops.{step}", side_effect=OSError("crash")):
            assert legacy_run(paths, "keep-staged") == 1
        assert legacy_run(paths, "keep-staged") == 0
    assert len(taken) <= 1   # one snapshot, however many runs
    assert find_rollback_target(paths, "myapp").ref == f"myapp-{V1}"
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == f"myapp-{V2}"


def test_a_crash_inside_prestage_to_previous_is_finished(paths, legacy) -> None:
    """The kept release moved to previous/, previous.json not yet written."""
    from boxmunge import legacy_stage_ops
    from tests.txn_helpers import fake_backups
    taken: list[dict] = []
    with fake_backups(taken):
        with patch.object(legacy_stage_ops, "previous_meta_text", side_effect=OSError("crash")):
            assert legacy_run(paths, "keep-staged") == 1
        assert not (legacy / ".releases" / "prestage" / "release").exists()
        assert legacy_run(paths, "keep-staged") == 0
    assert find_rollback_target(paths, "myapp").ref == f"myapp-{V1}"
    assert (legacy / ".releases" / "previous" / "VERSION").read_text() == "v1\n"


def test_a_linked_previous_on_the_rerun_branch_is_refused(paths, legacy, tmp_path,
                                                          capsys) -> None:
    from boxmunge import legacy_stage_ops
    from tests.txn_helpers import fake_backups
    taken: list[dict] = []
    with fake_backups(taken):
        with patch.object(legacy_stage_ops, "previous_meta_text", side_effect=OSError("crash")):
            assert legacy_run(paths, "keep-staged") == 1
        previous = legacy / ".releases" / "previous"
        previous.rename(tmp_path / "elsewhere")
        os.symlink(tmp_path / "elsewhere", previous)
        assert legacy_run(paths, "keep-staged") == 1
    assert "not a directory" in capsys.readouterr().err
    assert not (legacy / ".releases" / "previous.json").exists()


def test_staging_is_taken_down_once_across_reruns(paths, legacy) -> None:
    """After step 4 compose.yml is production's, which may lack the staging
    overlay's services: a rerun must not compose down with it again."""
    with patch("boxmunge.legacy_stage_ops._clean_up", side_effect=OSError("crash")):
        assert legacy_run(paths, "discard") == 1
    assert legacy_run.down.call_count == 1
    assert legacy_run(paths, "discard") == 0
    legacy_run.down.assert_not_called()


def test_after_the_last_step_only_the_recorded_choice_finishes(paths, legacy, capsys) -> None:
    with patch("boxmunge.legacy_stage_ops.finish_apply", side_effect=OSError("crash")):
        assert legacy_run(paths, "discard") == 1
    assert legacy_stage(paths, "myapp") is None
    assert legacy_run(paths, None) == 0
    assert "--discard" in capsys.readouterr().out
    legacy_run.up.assert_not_called()
    assert legacy_run(paths, "keep-staged") == 1
    assert "--discard" in capsys.readouterr().err
    assert get_record(paths, "myapp")["choice"] == "discard"
    assert legacy_run(paths, "discard") == 0
    assert get_record(paths, "myapp") is None


def test_a_stage_that_stops_being_detected_at_step_5_drops_its_state(paths) -> None:
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle
    from tests.txn_helpers import docker_off
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with docker_off():
        run_deploy("myapp", paths, ref=V1)
    (paths.project_dir("myapp") / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    state = legacy_staging_state(paths, "myapp")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"active": False}))
    with patch("boxmunge.legacy_stage_ops.drop_stage_record", side_effect=OSError("crash")):
        assert legacy_run(paths, "discard") == 1
    assert legacy_stage(paths, "myapp") is None and state.exists()
    assert legacy_run(paths, "discard") == 0
    assert not state.exists()


def test_after_a_crashed_never_deployed_discard_every_call_points_to_it(paths, never_deployed,
                                                                        capsys) -> None:
    with patch("boxmunge.legacy_stage_ops._clean_up", side_effect=OSError("crash")):
        assert legacy_run(paths, "discard") == 1
    capsys.readouterr()
    assert legacy_run(paths, None) == 0
    assert "--discard" in capsys.readouterr().out
    assert legacy_run(paths, "keep-staged") == 1
    err = capsys.readouterr().err
    assert "--discard" in err and "Cannot tell" not in err
