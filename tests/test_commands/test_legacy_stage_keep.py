# SPDX-License-Identifier: Apache-2.0
"""legacy-stage --keep-staged treats the staged release as promoted, with
production as the rollback target (bundle and git)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands.rollback import find_rollback_target
from boxmunge.legacy_stage import get_record, legacy_stage
from boxmunge.state import read_state, write_state
from tests.git_helpers import git
from tests.stage_helpers import V1, V2
from tests.test_commands.legacy_cmd_helpers import legacy_run


def test_keep_staged_makes_production_the_rollback_target(paths, legacy) -> None:
    from tests.txn_helpers import fake_backups
    taken: list[dict] = []
    with fake_backups(taken):
        assert legacy_run(paths, "keep-staged") == 0
    assert (legacy / "VERSION").read_text() == "v2\n"
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == f"myapp-{V2}"
    assert taken[0]["backup"]["type"] == "postgres"          # production's manifest
    target = find_rollback_target(paths, "myapp")
    assert target.ref == f"myapp-{V1}" and target.snapshot == "myapp-p1.tar.gz.age"
    assert legacy_stage(paths, "myapp") is None


def test_keep_staged_dumps_through_the_running_release_compose_file(paths, legacy) -> None:
    calls = []

    def backup(project_name, paths_, kind=None, manifest=None, compose_file=None):
        calls.append(compose_file)
        return 1
    with patch("boxmunge.commands.backup_cmd.backup_locked", backup):
        # A failed snapshot refuses: keeping the staged release without one
        # would leave rollback nothing to restore.
        assert legacy_run(paths, "keep-staged") == 1
    assert calls == [legacy / ".releases" / "prestage" / "release" / "compose.yml"]
    assert legacy_stage(paths, "myapp") is not None


def test_keep_staged_of_a_recreated_stage_pairs_with_the_snapshot_after_t(paths, legacy) -> None:
    snaps = paths.project_backups("myapp")
    snaps.mkdir(parents=True, exist_ok=True)
    for name in ("myapp-2026-10-01T110000-predeploy", "myapp-2026-10-01T130000-predeploy",
                 "myapp-2026-10-01T140000-nightly"):
        (snaps / f"{name}.tar.gz.age").write_text("s")
    with patch("boxmunge.commands.backup_cmd.backup_locked",
               side_effect=AssertionError("no snapshot is taken for a recreated stage")):
        assert legacy_run(paths, "keep-staged", created=(3,)) == 0
    target = find_rollback_target(paths, "myapp")
    assert target.snapshot == "myapp-2026-10-01T130000-predeploy.tar.gz.age"


def test_keep_staged_without_a_new_snapshot_is_refused(paths, legacy, capsys) -> None:
    snaps = paths.project_backups("myapp")
    snaps.mkdir(parents=True, exist_ok=True)
    (snaps / "myapp-2026-09-01T000000-predeploy.tar.gz.age").write_text("old")
    with patch("boxmunge.commands.backup_cmd.backup_locked", return_value=0):
        assert legacy_run(paths, "keep-staged") == 1
    assert "no new" in capsys.readouterr().err
    assert "snapshot" not in (get_record(paths, "myapp") or {})


@pytest.mark.parametrize("block", ["paused", "quarantined"])
def test_keep_staged_of_a_blocked_untouched_project_points_to_discard(paths, legacy, capsys,
                                                                     block) -> None:
    if block == "paused":
        from boxmunge.pause import write_paused_state
        write_paused_state("myapp", paths)
    else:
        write_state(paths.project_quarantine_state("myapp"), {"cve_id": "CVE-2099-0001"})
    with patch("boxmunge.commands.backup_cmd.backup_locked",
               side_effect=AssertionError("no backup of a blocked project")):
        assert legacy_run(paths, "keep-staged") == 1
    err = capsys.readouterr().err
    assert block in err and "--discard" in err


def test_a_kept_tree_missing_before_the_move_is_refused(paths, legacy, capsys) -> None:
    """An older previous/ must not be paired with the prestage's ref."""
    import shutil
    releases = legacy / ".releases"
    (releases / "previous").mkdir()
    (releases / "previous" / "VERSION").write_text("v0\n")
    shutil.rmtree(releases / "prestage" / "release")
    assert legacy_run(paths, "keep-staged", created=(3,)) == 1
    assert "prestage" in capsys.readouterr().err
    assert not (releases / "previous.json").exists()


def test_keep_staged_of_a_never_deployed_stage(paths, never_deployed) -> None:
    pdir = never_deployed
    with patch("boxmunge.commands.backup_cmd.backup_locked",
               side_effect=AssertionError("nothing was deployed to snapshot")):
        assert legacy_run(paths, "keep-staged") == 0
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == f"myapp-{V2}"
    assert not (pdir / ".releases" / "previous").exists()
    assert legacy_stage(paths, "myapp") is None


def test_git_keep_staged_records_the_full_sha(paths, legacy_git) -> None:
    a, b, repo, t = legacy_git
    from tests.txn_helpers import fake_backups
    taken: list[dict] = []
    with fake_backups(taken):
        assert legacy_run(paths, "keep-staged", at=t, created=(-1,)) == 0
    state = read_state(paths.project_deploy_state("myapp"))
    assert state["current_ref"] == b and state["history"][0]["ref"] == a[:7]
    assert state["pre_deploy_snapshot"] == "myapp-p1.tar.gz.age"
    assert taken[0]["backup"]["type"] == "postgres"          # the running commit's
    assert git("rev-parse", "HEAD", cwd=repo) == b


def test_never_deployed_git_keep_staged_records_the_staged_commit(paths, legacy_git) -> None:
    _, b, _, t = legacy_git
    write_state(paths.project_deploy_state("myapp"), {})
    with patch("boxmunge.commands.backup_cmd.backup_locked",
               side_effect=AssertionError("nothing was deployed to snapshot")):
        assert legacy_run(paths, "keep-staged", at=t, created=(-1,)) == 0
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == b
    legacy_run.up.assert_called_once()
