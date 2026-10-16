# SPDX-License-Identifier: Apache-2.0
"""An upgrade never replaces a git project's manifest.yml symlink.

`add-git-project` links `<p>/manifest.yml` into `repo/`. The upgrade's
manifest migration used to rename a migrated copy over that link, so every
later git deploy kept reading the frozen copy instead of the repository's
file. Real git and a real clone throughout; only container starts and the
Caddy reload are mocked.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.add_git_project_cmd import run_add_git_project
from boxmunge.commands.deploy_steps import update_repo
from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.manifest import CURRENT_SCHEMA_VERSION, load_manifest
from boxmunge.paths import BoxPaths
from tests.test_commands.test_upgrade_dry_run_and_pause import _setup

NAME = "gitapp"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    )


def _manifest(origin: Path, host: str) -> str:
    return yaml.safe_dump({
        "schema_version": 1, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "project": NAME, "source": "git", "repo": str(origin), "ref": "main",
        "hosts": [host],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }, sort_keys=False)


def _commit_manifest(origin: Path, host: str, message: str) -> None:
    (origin / "manifest.yml").write_text(_manifest(origin, host))
    _git(origin, "add", "manifest.yml")
    _git(origin, "commit", "-m", message)


@pytest.fixture
def git_project(tmp_path: Path) -> tuple[BoxPaths, Path]:
    paths = _setup(tmp_path)
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    (origin / "compose.yml").write_text("services:\n  web:\n    image: nginx:1.25\n")
    _git(origin, "add", "compose.yml")
    _commit_manifest(origin, "one.example.com", "initial")
    assert run_add_git_project(NAME, str(origin), paths) == 0
    return paths, origin


@patch("boxmunge.project_alerts.notify", return_value=True)
@patch("boxmunge.commands.upgrade_cmd.caddy_reload")
@patch("boxmunge.commands.upgrade_steps.compose_up")
def test_apply_keeps_symlink_and_uses_migrated_manifest(
    mock_up, _reload, mock_notify, git_project,
) -> None:
    paths, origin = git_project
    link = paths.project_manifest(NAME)
    repo = paths.project_dir(NAME) / "repo"
    written = (repo / "manifest.yml").read_bytes()

    assert run_upgrade(paths, apply_only=True) == 0

    assert link.is_symlink()
    assert link.resolve() == (repo / "manifest.yml").resolve()
    assert (repo / "manifest.yml").read_bytes() == written
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo,
                            check=True, capture_output=True, text=True)
    assert status.stdout == ""
    # The migrated manifest drove the upgrade: configs were regenerated
    # from it and the project restarted.
    assert "one.example.com" in paths.project_caddy_site(NAME).read_text()
    assert paths.project_compose_override(NAME).exists()
    mock_up.assert_called_once()
    assert load_manifest(link)["schema_version"] == CURRENT_SCHEMA_VERSION
    # The operator is told to update the repository's file.
    mock_notify.assert_called_once()
    assert "Update it in the repository" in mock_notify.call_args.args[2]

    # The link still follows the repository: a later commit is what the
    # next git deploy reads, migrated in memory.
    _commit_manifest(origin, "two.example.com", "move host")
    assert update_repo(repo, "main", load_manifest(link)) is not None
    manifest = load_manifest(link)
    assert manifest["hosts"] == ["two.example.com"]
    assert manifest["schema_version"] == CURRENT_SCHEMA_VERSION


@patch("boxmunge.project_alerts.notify", return_value=True)
@patch("boxmunge.commands.upgrade_cmd.caddy_reload")
@patch("boxmunge.commands.upgrade_steps.compose_up")
def test_second_upgrade_does_not_alert_again(_up, _reload, mock_notify, git_project) -> None:
    paths, _ = git_project
    assert run_upgrade(paths, apply_only=True) == 0
    assert run_upgrade(paths, apply_only=True) == 0
    mock_notify.assert_called_once()


def test_dry_run_reports_in_memory_migration(git_project, capsys) -> None:
    paths, _ = git_project
    assert run_upgrade(paths, dry_run=True) == 0
    out = capsys.readouterr().out
    assert f"{NAME}: repository manifest.yml uses schema v1" in out
    assert paths.project_manifest(NAME).is_symlink()
