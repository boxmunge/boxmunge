"""Git rollbacks in their own transaction: from the deploy history, and
from an open git install (plan Task 30)."""
from __future__ import annotations

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.rollback import run_rollback
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.release_txn import load_txn
from boxmunge.staged_release import load_slot
from boxmunge.state import read_state, write_state
from tests.git_helpers import commit, git
from tests.git_project_helpers import git_manifest, git_project
from tests.stage_helpers import staging_docker_off
from tests.txn_helpers import crash_at


def _head(pdir) -> str:
    return git("rev-parse", "HEAD", cwd=pdir / "repo")


def test_rollback_from_an_open_git_install(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    origin = tmp_path / "origin.git"
    commit(work, {"manifest.yml": git_manifest(origin, extra="deploy:\n  pre_deploy: 'false'\n")},
           "bad")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
        assert load_txn(paths, "myapp").phase == "hook_started"
        assert run_rollback("myapp", paths, yes=True) == 0
    assert _head(pdir) == before and load_txn(paths, "myapp") is None
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == before


def test_rollback_returns_to_the_previous_deploy(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    a = _head(pdir)
    b = commit(work, {"VERSION": "B\n"}, "B")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 0
        assert run_rollback("myapp", paths, yes=True) == 0
    assert _head(pdir) == a and load_txn(paths, "myapp") is None
    assert read_state(paths.project_deploy_state("myapp"))["history"][0]["ref"] == b


def test_a_short_history_ref_from_0_10_1_is_resolved(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    a = _head(pdir)
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=commit(work, {"VERSION": "B\n"}, "B")) == 0
    state = read_state(paths.project_deploy_state("myapp"))
    state["history"][0]["ref"] = a[:7]
    write_state(paths.project_deploy_state("myapp"), state)
    with staging_docker_off():
        assert run_rollback("myapp", paths, yes=True) == 0
    assert _head(pdir) == a


def test_a_crashed_rollback_resumes(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    a = _head(pdir)
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=commit(work, {"VERSION": "B\n"}, "B")) == 0
        assert crash_at("rollback.switching",
                        lambda: run_rollback("myapp", paths, yes=True)) == 137
        assert load_txn(paths, "myapp").source == "rollback"
        assert run_rollback("myapp", paths, yes=True) == 0
    assert _head(pdir) == a and load_txn(paths, "myapp") is None


def test_a_git_rollback_during_a_stage_leaves_staging(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    a = _head(pdir)
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=commit(work, {"VERSION": "B\n"}, "B")) == 0
        staged = commit(work, {"VERSION": "staged\n"}, "staged")
        assert run_stage("myapp", paths) == 0
        assert run_rollback("myapp", paths, yes=True) == 0
    assert _head(pdir) == a and load_slot(paths, "myapp").ref == staged
