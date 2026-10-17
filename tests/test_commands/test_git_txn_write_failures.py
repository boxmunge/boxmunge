"""A git install whose transaction record cannot be written (disk full, an
unreadable HEAD) fails with a clean error naming the way on, never a
traceback, and leaves what was recorded as it was."""
from __future__ import annotations

from unittest.mock import patch

from boxmunge import release_txn
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.rollback import run_rollback
from boxmunge.git_slot import GitRefError
from boxmunge.release_txn import load_txn
from tests.git_helpers import commit, git
from tests.git_project_helpers import git_manifest, git_project
from tests.stage_helpers import staging_docker_off

FULL = OSError(28, "No space left on device")


def _head(pdir) -> str:
    return git("rev-parse", "HEAD", cwd=pdir / "repo")


def _fail_on(phase: str, error: Exception):
    real = release_txn.advance

    def advance(paths, project, txn, to):
        if to == phase:
            raise error
        return real(paths, project, txn, to)
    return advance


def test_a_first_deploy_whose_record_cannot_be_opened(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path, deploy=False)
    before = _head(pdir)
    commit(work, {"VERSION": "B\n"}, "B")
    with staging_docker_off(), \
            patch("boxmunge.commands.git_deploy.open_txn", side_effect=FULL):
        assert run_deploy("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "Recording the install" in err and "Nothing was changed" in err
    assert _head(pdir) == before and load_txn(paths, "myapp") is None


def test_previous_kept_that_cannot_be_recorded_leaves_the_install_at_committed(
        paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    commit(work, {"VERSION": "B\n"}, "B")
    with staging_docker_off(), patch("boxmunge.commands.git_deploy.advance",
                                     _fail_on("previous_kept", GitRefError("no HEAD"))):
        assert run_deploy("myapp", paths) == 1
    assert "recording its progress failed: no HEAD" in capsys.readouterr().err
    assert load_txn(paths, "myapp").phase == "committed" and _head(pdir) == before


def test_installed_that_cannot_be_recorded_names_the_ways_on(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    tip = commit(work, {"VERSION": "B\n"}, "B")
    with staging_docker_off(), patch("boxmunge.commands.git_deploy.advance",
                                     _fail_on("installed", FULL)):
        assert run_deploy("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "recording that failed" in err and "--abandon" in err
    assert load_txn(paths, "myapp").phase == "previous_kept" and _head(pdir) == tip
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=tip) == 0   # the rerun finishes it
    assert load_txn(paths, "myapp") is None


def test_a_fix_forward_that_cannot_be_recorded_leaves_the_open_install(paths, tmp_path,
                                                                       capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    origin = tmp_path / "origin.git"
    commit(work, {"manifest.yml": git_manifest(origin, extra="deploy:\n  pre_deploy: 'false'\n")},
           "bad")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
    failed = load_txn(paths, "myapp")
    commit(work, {"manifest.yml": git_manifest(origin)}, "fix")
    with staging_docker_off(), \
            patch("boxmunge.commands.git_deploy.supersede_txn", side_effect=FULL):
        assert run_deploy("myapp", paths) == 1
    assert "That install is as it was" in capsys.readouterr().err
    assert load_txn(paths, "myapp") == failed


def test_a_rollback_whose_record_cannot_be_written(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    a = _head(pdir)
    b = commit(work, {"VERSION": "B\n"}, "B")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 0
    with staging_docker_off(), \
            patch("boxmunge.commands.rollback_git.open_txn", side_effect=FULL):
        assert run_rollback("myapp", paths, yes=True) == 1
    assert "Recording the rollback" in capsys.readouterr().err
    assert load_txn(paths, "myapp") is None and _head(pdir) == b
    with staging_docker_off(), patch("boxmunge.commands.rollback_git.advance",
                                     _fail_on("installed", FULL)):
        assert run_rollback("myapp", paths, yes=True) == 1
    assert "Rerun 'rollback myapp'" in capsys.readouterr().err
    with staging_docker_off():
        assert run_rollback("myapp", paths, yes=True) == 0
    assert _head(pdir) == a and load_txn(paths, "myapp") is None
