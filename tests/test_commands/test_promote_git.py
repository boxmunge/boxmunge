"""Promote deploys exactly the staged SHA, whatever the branch did since
(spec D10; plan Task 31)."""
from __future__ import annotations

from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.release_txn import load_txn
from boxmunge.staged_release import load_slot, update_meta
from boxmunge.state import read_state
from tests.git_helpers import commit, git
from tests.git_project_helpers import git_manifest, git_project
from tests.stage_helpers import staging_docker_off
from tests.txn_helpers import crash_at


def _head(pdir) -> str:
    return git("rev-parse", "HEAD", cwd=pdir / "repo")


def test_promote_deploys_the_staged_sha_after_the_branch_moved(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    a = commit(work, {"VERSION": "A2\n"}, "A2")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
        commit(work, {"VERSION": "C\n"}, "C")
        assert run_promote("myapp", paths) == 0
    assert _head(pdir) == a and load_slot(paths, "myapp") is None
    assert load_txn(paths, "myapp") is None
    state = read_state(paths.project_deploy_state("myapp"))
    assert state["current_ref"] == a and state["history"][0]["ref"] == before


def test_unstage_leaves_production_at_its_commit(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    b = _head(pdir)
    commit(work, {"VERSION": "A2\n"}, "A2")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
        assert run_unstage("myapp", paths) == 0
    assert _head(pdir) == b


def test_a_killed_promote_resumes_the_same_sha(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    a = commit(work, {"VERSION": "A2\n"}, "A2")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
        assert crash_at("txn.installed", lambda: run_promote("myapp", paths)) == 137
        txn = load_txn(paths, "myapp")
        assert (txn.source, txn.ref, txn.staged_id) == ("staged", a, load_slot(paths, "myapp").id)
        commit(work, {"VERSION": "C\n"}, "C")
        assert run_promote("myapp", paths) == 0
    assert _head(pdir) == a and load_slot(paths, "myapp") is None


def test_a_failed_hook_leaves_the_stage_promotable(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    origin = tmp_path / "origin.git"
    commit(work, {"manifest.yml": git_manifest(origin, extra="deploy:\n  pre_deploy: 'false'\n")},
           "bad hook")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
        assert run_promote("myapp", paths) == 1
    assert load_txn(paths, "myapp").phase == "hook_started"
    assert load_slot(paths, "myapp").state == "ready" and _head(pdir) != before


def test_a_slot_ref_that_is_not_a_full_sha_is_refused(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    a = commit(work, {"VERSION": "A2\n"}, "A2")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
        update_meta(paths, "myapp", load_slot(paths, "myapp"), ref=a[:12])
        assert run_promote("myapp", paths) == 1
    assert "stage it again" in capsys.readouterr().err
    assert _head(pdir) == before and load_txn(paths, "myapp") is None


def test_a_commit_production_no_longer_has_is_refused(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
        update_meta(paths, "myapp", load_slot(paths, "myapp"), ref="1" * 40)
        assert run_promote("myapp", paths) == 1
    assert "no longer has" in capsys.readouterr().err
    assert _head(pdir) == before and load_txn(paths, "myapp") is None
