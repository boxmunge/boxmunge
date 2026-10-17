# SPDX-License-Identifier: Apache-2.0
"""A crash after each step of a git or never-deployed resolution is finished
by running the same command again (the bundle cases: test_legacy_stage_cmd)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.legacy_stage import get_record, legacy_stage
from boxmunge.state import read_state
from tests.git_helpers import git
from tests.test_commands.test_legacy_stage_cmd import _never_deployed_stage, _run

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
            assert _run(paths, choice, at=t, created=(-1,)) == 1
        assert _run(paths, choice, at=t, created=(-1,)) == 0
    assert git("rev-parse", "HEAD", cwd=repo) == (a if choice == "discard" else b)
    assert legacy_stage(paths, "myapp") is None and get_record(paths, "myapp") is None
    if choice == "keep-staged":
        assert len(taken) == 1   # one snapshot, however many runs
        assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == b


@pytest.mark.parametrize("step", STEPS)
def test_a_crashed_never_deployed_keep_staged_is_finished(paths, step) -> None:
    from tests.stage_helpers import V2
    pdir = _never_deployed_stage(paths)
    with patch("boxmunge.commands.backup_cmd.backup_locked",
               side_effect=AssertionError("nothing was deployed to snapshot")):
        with patch(f"boxmunge.legacy_stage_ops.{step}", side_effect=OSError("crash")):
            assert _run(paths, "keep-staged") == 1
        assert _run(paths, "keep-staged") == 0
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == f"myapp-{V2}"
    assert legacy_stage(paths, "myapp") is None and get_record(paths, "myapp") is None

