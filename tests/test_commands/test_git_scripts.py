"""A git project's boxmunge-scripts/ is its checked-out commit's: every
production checkout (deploy, rollback, abandon) and every git slot puts the
commit's scripts where the overlay mounts them and pre_deploy runs them, and
a deploy whose manifest names a script the commit lacks is refused before
compose runs."""
from __future__ import annotations

import os
from unittest.mock import patch

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.install_abandon import run_abandon
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.rollback import run_rollback
from boxmunge.commands.smoke_result import SmokeResult
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.validate import run_validate
from tests.git_helpers import commit, git
from tests.git_project_helpers import git_manifest, git_project
from tests.stage_helpers import staging_docker_off

SMOKE = "    smoke: boxmunge-scripts/smoke.sh\n"


def _with_smoke(origin) -> str:
    return git_manifest(origin).replace("      - path: /\n", "      - path: /\n" + SMOKE)


def _smoke_passes():
    return patch("boxmunge.commands.check._smoke_one",
                 new=lambda *a, **k: SmokeResult("ok", ""))


def test_a_deploy_installs_the_commits_scripts(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    commit(work, {"manifest.yml": _with_smoke(tmp_path / "origin.git"),
                  "boxmunge-scripts/smoke.sh": "echo one\n"}, "smoke")
    with staging_docker_off(), _smoke_passes():
        assert run_deploy("myapp", paths) == 0
    smoke = pdir / "boxmunge-scripts" / "smoke.sh"
    assert smoke.read_text() == "echo one\n" and os.stat(smoke).st_mode & 0o111
    inode = os.stat(pdir / "boxmunge-scripts").st_ino
    commit(work, {"boxmunge-scripts/smoke.sh": "echo two\n"}, "smoke two")
    with staging_docker_off(), _smoke_passes():
        assert run_deploy("myapp", paths) == 0
    assert smoke.read_text() == "echo two\n"
    # Refreshed in place: a running container's bind mount keeps resolving.
    assert os.stat(pdir / "boxmunge-scripts").st_ino == inode


def test_an_empty_directory_docker_left_is_filled(paths, tmp_path) -> None:
    """Before this, Docker created a missing ./boxmunge-scripts empty."""
    pdir, work = git_project(paths, tmp_path)
    (pdir / "boxmunge-scripts").mkdir()
    commit(work, {"manifest.yml": _with_smoke(tmp_path / "origin.git"),
                  "boxmunge-scripts/smoke.sh": "echo one\n"}, "smoke")
    with staging_docker_off(), _smoke_passes():
        assert run_deploy("myapp", paths) == 0
    assert (pdir / "boxmunge-scripts" / "smoke.sh").read_text() == "echo one\n"


def test_a_missing_smoke_script_is_refused_before_compose(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    commit(work, {"manifest.yml": _with_smoke(tmp_path / "origin.git")}, "smoke, no script")
    with staging_docker_off() as docker:
        assert run_deploy("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "smoke 'boxmunge-scripts/smoke.sh' runs /boxmunge-scripts/smoke.sh" in err
    assert "the commit has no boxmunge-scripts/, and the project directory has no" in err
    docker["up"].assert_not_called()  # a fresh patch: this deploy started nothing
    assert not os.path.lexists(pdir / "boxmunge-scripts")


def test_a_relative_pre_deploy_must_be_in_the_release(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    commit(work, {"manifest.yml": git_manifest(
        tmp_path / "origin.git", extra="deploy:\n  pre_deploy: 'scripts/migrate.sh'\n"),
        "scripts/migrate.sh": "true\n"}, "hook outside boxmunge-scripts")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "deploy.pre_deploy runs 'scripts/migrate.sh'" in err
    assert "commit the script under boxmunge-scripts/" in err


def test_rollback_puts_the_older_commits_scripts_back(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    commit(work, {"manifest.yml": _with_smoke(tmp_path / "origin.git"),
                  "boxmunge-scripts/smoke.sh": "echo one\n"}, "one")
    with staging_docker_off(), _smoke_passes():
        assert run_deploy("myapp", paths) == 0
        commit(work, {"boxmunge-scripts/smoke.sh": "echo two\n"}, "two")
        assert run_deploy("myapp", paths) == 0
        assert run_rollback("myapp", paths, yes=True) == 0
    assert (pdir / "boxmunge-scripts" / "smoke.sh").read_text() == "echo one\n"


def test_a_commit_without_scripts_leaves_the_existing_ones(paths, tmp_path, capsys) -> None:
    """Scripts placed by hand before 0.12 keep working, also for a rollback
    to a commit made before them."""
    pdir, work = git_project(paths, tmp_path)
    (pdir / "boxmunge-scripts").mkdir()
    (pdir / "boxmunge-scripts" / "smoke.sh").write_text("echo by hand\n")
    inode = os.stat(pdir / "boxmunge-scripts").st_ino
    commit(work, {"manifest.yml": _with_smoke(tmp_path / "origin.git")}, "smoke, no scripts")
    with staging_docker_off(), _smoke_passes():
        assert run_deploy("myapp", paths) == 0
    assert (pdir / "boxmunge-scripts" / "smoke.sh").read_text() == "echo by hand\n"
    assert os.stat(pdir / "boxmunge-scripts").st_ino == inode
    assert "the checked-out commit carries no boxmunge-scripts/" in capsys.readouterr().out


def test_staging_a_never_deployed_project_names_prod_deploy(paths, tmp_path, capsys) -> None:
    git_project(paths, tmp_path, deploy=False)
    with staging_docker_off():
        assert run_stage("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "'myapp' has never been deployed to production" in err
    assert "'prod-deploy myapp'" in err


def test_copy_data_after_a_failed_first_deploy_names_prod_deploy(paths, tmp_path,
                                                                  capsys) -> None:
    """A first deploy that failed leaves an overlay but records no deploy:
    there is still no production data for staging.copy_data to copy."""
    pdir, work = git_project(paths, tmp_path, deploy=False)
    commit(work, {"manifest.yml": git_manifest(tmp_path / "origin.git",
                                               extra="staging:\n  copy_data: true\n")}, "copy")
    git("pull", "-q", cwd=pdir / "repo")
    (pdir / "compose.boxmunge.yml").write_text("services: {}\n")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "nor data for staging.copy_data to copy" in err and "'prod-deploy myapp'" in err


def test_a_refused_deploy_then_abandon_keeps_the_mounted_directory(paths, tmp_path,
                                                                   capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    commit(work, {"manifest.yml": _with_smoke(tmp_path / "origin.git"),
                  "boxmunge-scripts/smoke.sh": "echo one\n"}, "one")
    with staging_docker_off(), _smoke_passes():
        assert run_deploy("myapp", paths) == 0
    inode = os.stat(pdir / "boxmunge-scripts").st_ino
    git("rm", "-q", "boxmunge-scripts/smoke.sh", cwd=work)
    commit(work, {"boxmunge-scripts/other.sh": "true\n"}, "smoke.sh gone")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1   # refused after the checkout
        assert run_abandon("myapp", paths) == 0
    assert (pdir / "boxmunge-scripts" / "smoke.sh").read_text() == "echo one\n"
    assert not (pdir / "boxmunge-scripts" / "other.sh").exists()
    assert os.stat(pdir / "boxmunge-scripts").st_ino == inode


def test_promote_installs_the_staged_commits_scripts(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    commit(work, {"manifest.yml": _with_smoke(tmp_path / "origin.git"),
                  "boxmunge-scripts/smoke.sh": "echo staged\n"}, "smoke")
    with staging_docker_off(), _smoke_passes():
        assert run_stage("myapp", paths) == 0
        assert not (pdir / "boxmunge-scripts").exists()  # production not touched yet
        assert run_promote("myapp", paths) == 0
    assert (pdir / "boxmunge-scripts" / "smoke.sh").read_text() == "echo staged\n"


def test_committed_scripts_that_are_not_a_directory_are_refused(paths, tmp_path,
                                                                 capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    commit(work, {"boxmunge-scripts": "not a directory\n"}, "a file")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
    assert "boxmunge-scripts is not a directory" in capsys.readouterr().err
    os.unlink(work / "boxmunge-scripts")
    os.symlink("elsewhere", work / "boxmunge-scripts")
    commit(work, {}, "a link")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
    assert "boxmunge-scripts is a symbolic link" in capsys.readouterr().err


def test_a_link_inside_the_committed_scripts_is_refused(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    (work / "boxmunge-scripts").mkdir()
    (work / "boxmunge-scripts" / "real.sh").write_text("true\n")
    os.symlink("real.sh", work / "boxmunge-scripts" / "smoke.sh")
    sha = commit(work, {"manifest.yml": _with_smoke(tmp_path / "origin.git")}, "linked smoke")
    git("fetch", "-q", "origin", cwd=pdir / "repo")
    git("checkout", "-q", "--detach", sha, cwd=pdir / "repo")
    assert run_validate("myapp", paths) == 1
    assert "boxmunge-scripts/smoke.sh is a symbolic link" in capsys.readouterr().err
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "commit the scripts as regular files" in err
    assert not os.path.lexists(pdir / "boxmunge-scripts")
