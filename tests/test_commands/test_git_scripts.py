"""A git project's boxmunge-scripts/ is its checked-out commit's: every
production checkout (deploy, rollback, abandon) and every git slot puts the
commit's scripts where the overlay mounts them and pre_deploy runs them, and
a deploy whose manifest names a script the commit lacks is refused before
compose runs."""
from __future__ import annotations

import os
from unittest.mock import patch

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.rollback import run_rollback
from boxmunge.commands.smoke_result import SmokeResult
from boxmunge.commands.stage_cmd import run_stage
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
    assert "the repository has no boxmunge-scripts/smoke.sh at this commit" in err
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


def test_a_commit_without_scripts_removes_them(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    commit(work, {"manifest.yml": _with_smoke(tmp_path / "origin.git"),
                  "boxmunge-scripts/smoke.sh": "echo one\n"}, "smoke")
    with staging_docker_off(), _smoke_passes():
        assert run_deploy("myapp", paths) == 0
    git("rm", "-q", "-r", "boxmunge-scripts", cwd=work)
    commit(work, {"manifest.yml": git_manifest(tmp_path / "origin.git")}, "no smoke")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 0
    assert not os.path.lexists(pdir / "boxmunge-scripts")
    assert "the checked-out commit has none" in capsys.readouterr().out


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
