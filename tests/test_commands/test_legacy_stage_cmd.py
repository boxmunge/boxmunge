"""legacy-stage resolves a 0.10.1 stage once a platform rollback is impossible."""
from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

from boxmunge.commands.legacy_stage_cmd import cmd_legacy_stage, legacy_stage_locked
from boxmunge.commands.rollback import find_rollback_target
from boxmunge.legacy_stage import get_record, legacy_stage, legacy_staging_state
from boxmunge.state import read_state, write_state
from boxmunge.upgrade_state import write_probation
from tests.bundle_helpers import SAFE_COMPOSE
from tests.git_helpers import git
from tests.legacy_helpers import legacy_bundle_stage, legacy_git_stage, reflog_checkout_time, stamp
from tests.stage_helpers import V1, V2, staging_docker_off
from tests.test_legacy_stage_evidence import T, _created


@pytest.fixture
def legacy(paths):
    pdir = legacy_bundle_stage(paths)
    stamp(pdir / ".releases" / "prestage" / "meta.json", T)
    return pdir


@pytest.fixture
def legacy_git(paths, tmp_path):
    (tmp_path / "src").mkdir()
    a, b = legacy_git_stage(paths, tmp_path / "src")
    (paths.project_dir("myapp") / "compose.yml").write_text(SAFE_COMPOSE)
    repo = paths.project_dir("myapp") / "repo"
    return a, b, repo, reflog_checkout_time(repo)


def _run(paths, choice, confirm=False, created=(-5,), at=T):
    with staging_docker_off() as docker, \
            patch("boxmunge.docker_containers.created_times",
                  return_value=_created(*created, at=at)), \
            patch("boxmunge.legacy_stage_ops.compose_down") as down, \
            patch("boxmunge.legacy_stage_ops.caddy_reload"), \
            patch("boxmunge.legacy_stage_ops.notify") as sent, \
            patch("boxmunge.legacy_stage.notify", return_value=True):
        rc = legacy_stage_locked(paths, "myapp", choice, confirm)
    # The latest run's mocks, for the assertions.
    _run.up, _run.down, _run.sent = docker["up"], down, sent
    return rc


def test_refused_during_probation(paths, legacy, capsys) -> None:
    write_probation(paths, "0.11.0b1", "b", hours=6)
    assert _run(paths, "discard") == 1
    err = capsys.readouterr().err
    assert "probation" in err and "until" in err
    assert legacy_stage(paths, "myapp") is not None
    assert (get_record(paths, "myapp") or {}).get("choice") is None


@pytest.mark.parametrize("marker", ["upgrade-inflight", "rollback-inflight"])
def test_refused_while_an_upgrade_or_rollback_is_interrupted(paths, legacy, capsys,
                                                            marker) -> None:
    (paths.root / "env-b").mkdir(parents=True, exist_ok=True)
    (paths.root / "env-b" / marker).write_text("")
    assert _run(paths, "keep-staged") == 1
    assert marker in capsys.readouterr().err
    assert legacy_stage(paths, "myapp") is not None


def test_no_flag_shows_the_evidence_and_changes_nothing(paths, legacy, capsys) -> None:
    from tests.bundle_helpers import tree_snapshot
    before = tree_snapshot(legacy)
    assert _run(paths, None) == 0
    out = capsys.readouterr().out
    assert "untouched" in out and "--discard" in out and "--keep-staged" in out
    assert tree_snapshot(legacy) == before
    assert get_record(paths, "myapp") is None


def test_no_flag_during_probation_still_shows_the_evidence(paths, legacy, capsys) -> None:
    write_probation(paths, "0.11.0b1", "b", hours=6)
    assert _run(paths, None) == 0
    out = capsys.readouterr().out
    assert "untouched" in out and "probation" in out


def test_discard_of_an_untouched_stage_puts_production_back(paths, legacy) -> None:
    assert _run(paths, "discard") == 0
    assert (legacy / "VERSION").read_text() == "v1\n"
    assert json.loads((legacy / ".releases" / "live.json").read_text())["ref"] == f"myapp-{V1}"
    assert legacy_stage(paths, "myapp") is None and get_record(paths, "myapp") is None
    assert not (legacy / "compose.staging-base.yml").exists()
    assert not (legacy / "compose.boxmunge-staging.yml").exists()
    assert not (legacy / ".releases" / "prestage").exists()
    assert not legacy_staging_state(paths, "myapp").exists()
    # Staging was taken down with the legacy files; production recreated on the overlay.
    assert _run.down.call_args.kwargs["compose_files"] == [
        "compose.staging-base.yml", "compose.boxmunge-staging.yml"]
    assert _run.down.call_args.kwargs["project_name"] == "myapp-staging"
    assert _run.up.call_args.kwargs["compose_files"] == ["compose.yml", "compose.boxmunge.yml"]
    assert (legacy / "compose.boxmunge.yml").exists()
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == f"myapp-{V1}"
    assert _run.sent.call_args.kwargs["priority"] == 0
    assert "--discard" in _run.sent.call_args.args[2]


def test_discard_removes_the_staging_site(paths, legacy) -> None:
    site = paths.project_staging_caddy_site("myapp")
    site.parent.mkdir(parents=True, exist_ok=True)
    site.write_text("staging.example.com {}\n")
    assert _run(paths, "discard") == 0
    assert not site.exists()


def test_discard_of_a_recreated_stage_needs_confirmation(paths, legacy, capsys) -> None:
    snaps = paths.project_backups("myapp")
    snaps.mkdir(parents=True, exist_ok=True)
    (snaps / "myapp-2026-10-01T130000-predeploy.tar.gz.age").write_text("s")
    assert _run(paths, "discard", created=(3,)) == 1
    err = capsys.readouterr().err
    assert "--confirm-recreated" in err and "myapp-2026-10-01T130000-predeploy" in err
    assert (get_record(paths, "myapp") or {}).get("choice") is None
    assert _run(paths, "discard", confirm=True, created=(3,)) == 0
    assert (legacy / "VERSION").read_text() == "v1\n"


def test_keep_staged_makes_production_the_rollback_target(paths, legacy) -> None:
    from tests.txn_helpers import fake_backups
    taken: list[dict] = []
    with fake_backups(taken):
        assert _run(paths, "keep-staged") == 0
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
        assert _run(paths, "keep-staged") == 1
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
        assert _run(paths, "keep-staged", created=(3,)) == 0
    target = find_rollback_target(paths, "myapp")
    assert target.snapshot == "myapp-2026-10-01T130000-predeploy.tar.gz.age"


def test_a_different_choice_on_rerun_is_refused(paths, legacy, capsys) -> None:
    with patch("boxmunge.legacy_stage_ops._production_code", side_effect=OSError("crash")):
        assert _run(paths, "discard") == 1
    assert _run(paths, "keep-staged") == 1
    assert "--discard" in capsys.readouterr().err
    assert _run(paths, "discard") == 0


@pytest.mark.parametrize("step", ["_stop_legacy_staging", "_remove_staging_site",
                                  "_production_code", "_clean_up", "_drop_stage_record",
                                  "finish_apply"])
def test_a_crash_after_each_step_is_finished_by_the_same_command(paths, legacy, step) -> None:
    with patch(f"boxmunge.legacy_stage_ops.{step}", side_effect=OSError("crash")):
        assert _run(paths, "discard") == 1
    assert _run(paths, "discard") == 0
    assert (legacy / "VERSION").read_text() == "v1\n" and get_record(paths, "myapp") is None


@pytest.mark.parametrize("step", ["_production_code", "_clean_up", "_drop_stage_record",
                                  "finish_apply"])
def test_a_crash_during_keep_staged_is_finished_by_the_same_command(paths, legacy,
                                                                   step) -> None:
    from tests.txn_helpers import fake_backups
    taken: list[dict] = []
    with fake_backups(taken):
        with patch(f"boxmunge.legacy_stage_ops.{step}", side_effect=OSError("crash")):
            assert _run(paths, "keep-staged") == 1
        assert _run(paths, "keep-staged") == 0
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
            assert _run(paths, "keep-staged") == 1
        assert not (legacy / ".releases" / "prestage" / "release").exists()
        assert _run(paths, "keep-staged") == 0
    assert find_rollback_target(paths, "myapp").ref == f"myapp-{V1}"
    assert (legacy / ".releases" / "previous" / "VERSION").read_text() == "v1\n"


def test_leftover_allows_only_discard(paths, capsys) -> None:
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle
    from tests.txn_helpers import docker_off
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with docker_off():
        run_deploy("myapp", paths, ref=V1)
    (paths.project_dir("myapp") / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    assert _run(paths, "keep-staged") == 1
    assert "--discard" in capsys.readouterr().err
    assert _run(paths, "discard") == 0
    assert legacy_stage(paths, "myapp") is None


def test_nothing_to_resolve(paths, capsys) -> None:
    assert _run(paths, "discard") == 1
    assert "no release staged by boxmunge 0.10.1" in capsys.readouterr().err


def test_a_paused_project_is_resolved_but_not_started(paths, legacy, capsys) -> None:
    from boxmunge.pause import write_paused_state
    write_paused_state("myapp", paths)
    assert _run(paths, "discard") == 0
    _run.up.assert_not_called()
    assert "not started" in capsys.readouterr().out
    assert legacy_stage(paths, "myapp") is None


# -- git --------------------------------------------------------------------

def test_git_discard_checks_out_the_deployed_commit(paths, legacy_git) -> None:
    a, _, repo, t = legacy_git
    assert _run(paths, "discard", at=t, created=(-1,)) == 0
    assert git("rev-parse", "HEAD", cwd=repo) == a
    detached = subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=repo)
    assert detached.returncode == 1
    assert legacy_stage(paths, "myapp") is None


def test_git_keep_staged_records_the_full_sha(paths, legacy_git) -> None:
    a, b, repo, t = legacy_git
    from tests.txn_helpers import fake_backups
    taken: list[dict] = []
    with fake_backups(taken):
        assert _run(paths, "keep-staged", at=t, created=(-1,)) == 0
    state = read_state(paths.project_deploy_state("myapp"))
    assert state["current_ref"] == b and state["history"][0]["ref"] == a[:7]
    assert state["pre_deploy_snapshot"] == "myapp-p1.tar.gz.age"
    assert taken[0]["backup"]["type"] == "postgres"          # the running commit's
    assert git("rev-parse", "HEAD", cwd=repo) == b


def test_git_discard_with_an_unresolvable_deployed_commit_is_refused(paths, legacy_git,
                                                                     capsys) -> None:
    *_, t = legacy_git
    write_state(paths.project_deploy_state("myapp"), {"current_ref": "0" * 40})
    assert _run(paths, "discard", confirm=True, at=t, created=(1,)) == 1
    assert "0" * 40 in capsys.readouterr().err
    assert legacy_stage(paths, "myapp") is not None


# -- argv -------------------------------------------------------------------

@pytest.mark.parametrize("argv", [["myapp", "--discard", "--keep-staged"],
                                  ["myapp", "--confirm-recreated"],
                                  ["myapp", "--keep-staged", "--confirm-recreated"],
                                  [], ["myapp", "--force"]])
def test_bad_arguments_are_usage_errors(argv) -> None:
    with pytest.raises(SystemExit) as e:
        cmd_legacy_stage(argv)
    assert e.value.code == 2


@pytest.mark.parametrize("argv, expected", [
    (["myapp"], (None, False)), (["myapp", "--discard"], ("discard", False)),
    (["myapp", "--discard", "--confirm-recreated"], ("discard", True)),
    (["myapp", "--keep-staged"], ("keep-staged", False))])
def test_arguments_choose_the_action(argv, expected) -> None:
    with patch("boxmunge.commands.legacy_stage_cmd.run_legacy_stage", return_value=0) as run, \
            pytest.raises(SystemExit) as e:
        cmd_legacy_stage(argv)
    assert e.value.code == 0
    assert run.call_args.args[1:] == ("myapp", *expected)


def test_staging_is_taken_down_once_across_reruns(paths, legacy) -> None:
    """After step 4 compose.yml is production's, which may lack the staging
    overlay's services: a rerun must not compose down with it again."""
    with patch("boxmunge.legacy_stage_ops._clean_up", side_effect=OSError("crash")):
        assert _run(paths, "discard") == 1
    assert _run.down.call_count == 1
    assert _run(paths, "discard") == 0
    _run.down.assert_not_called()


def test_after_the_last_step_only_the_recorded_choice_finishes(paths, legacy, capsys) -> None:
    with patch("boxmunge.legacy_stage_ops.finish_apply", side_effect=OSError("crash")):
        assert _run(paths, "discard") == 1
    assert legacy_stage(paths, "myapp") is None
    assert _run(paths, None) == 0
    assert "--discard" in capsys.readouterr().out
    _run.up.assert_not_called()
    assert _run(paths, "keep-staged") == 1
    assert "--discard" in capsys.readouterr().err
    assert get_record(paths, "myapp")["choice"] == "discard"
    assert _run(paths, "discard") == 0
    assert get_record(paths, "myapp") is None
