"""Git now runs as the deploy user, also under sudo: the upgrade's dry run
and apply name each git project whose repo/ deploy does not own, with
the chown that fixes it, and carry on."""
from __future__ import annotations

import pwd
from unittest.mock import patch

import pytest

from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.commands.upgrade_steps import check_upgrade
from boxmunge.git_layout import repo_ownership_advice
from tests.test_commands.test_upgrade_git_manifest import NAME, git_project  # noqa: F401


def _deploy_is(monkeypatch, uid: int) -> None:
    monkeypatch.setattr(pwd, "getpwnam", lambda name: pwd.struct_passwd(
        (name, "x", uid, uid, "", "/home/deploy", "/bin/sh")))


def test_a_repo_deploy_owns_needs_nothing(git_project, monkeypatch) -> None:  # noqa: F811
    paths, _ = git_project
    repo = paths.project_dir(NAME) / "repo"
    _deploy_is(monkeypatch, repo.stat().st_uid)
    assert repo_ownership_advice(paths.project_dir(NAME)) is None
    assert not any("deploy user" in line for line in check_upgrade(paths))


def test_the_dry_run_names_a_repo_deploy_does_not_own(git_project, monkeypatch) -> None:  # noqa: F811
    paths, _ = git_project
    repo = paths.project_dir(NAME) / "repo"
    _deploy_is(monkeypatch, repo.stat().st_uid + 1)
    lines = [line for line in check_upgrade(paths) if "deploy user" in line]
    assert len(lines) == 1                      # one line for the project
    assert lines[0].startswith(f"WARNING {NAME}: {repo}")
    assert f"chown -R deploy:deploy {repo}" in lines[0]


@patch("boxmunge.project_alerts.notify", return_value=True)
@patch("boxmunge.commands.upgrade_cmd.caddy_reload")
@patch("boxmunge.compose_guard.compose_up")
def test_the_apply_warns_and_goes_on(_up, _reload, _notify, git_project, monkeypatch,  # noqa: F811
                                     capsys) -> None:
    paths, _ = git_project
    repo = paths.project_dir(NAME) / "repo"
    _deploy_is(monkeypatch, repo.stat().st_uid + 1)
    assert run_upgrade(paths, apply_only=True) == 0
    assert f"chown -R deploy:deploy {repo}" in capsys.readouterr().err


@pytest.mark.parametrize("missing", [True, False])
def test_bundle_projects_and_boxes_without_deploy_are_not_checked(tmp_path, monkeypatch,
                                                                  missing) -> None:
    project = tmp_path / "bundleapp"
    project.mkdir()
    if missing:
        def no_deploy(name):
            raise KeyError(name)
        monkeypatch.setattr(pwd, "getpwnam", no_deploy)
        (project / "repo").mkdir()
    assert repo_ownership_advice(project) is None
