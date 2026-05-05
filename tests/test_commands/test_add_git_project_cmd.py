"""Tests for boxmunge add-git-project command."""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from boxmunge.commands.add_git_project_cmd import run_add_git_project
from boxmunge.log import _reset_logger
from boxmunge.paths import BoxPaths
from boxmunge.state import read_state

VALID_MANIFEST = """\
id: 01TESTULID0000000000000000
project: testapp
source: git
repo: git@github.com:org/testapp.git
ref: main
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
"""

class TestRunAddGitProject:
    @patch("boxmunge.commands.add_git_project_cmd.subprocess.run")
    def test_creates_project_dir(self, mock_run: MagicMock,
                                  paths: BoxPaths, tmp_path: Path) -> None:
        def fake_clone(cmd, **kwargs):
            if cmd[0] == "git" and cmd[1] == "clone":
                repo_dir = Path(cmd[-1])
                repo_dir.mkdir(parents=True, exist_ok=True)
                (repo_dir / "manifest.yml").write_text(VALID_MANIFEST)
                (repo_dir / "compose.yml").write_text(
                    "services:\n  web:\n    image: nginx\n"
                )
            return MagicMock(returncode=0, stdout="", stderr="")
        mock_run.side_effect = fake_clone

        result = run_add_git_project(
            "testapp", "git@github.com:org/testapp.git", paths, ref="main"
        )
        assert result == 0
        assert paths.project_dir("testapp").exists()

    @patch("boxmunge.commands.add_git_project_cmd.subprocess.run")
    def test_records_deploy_state(self, mock_run: MagicMock,
                                   paths: BoxPaths, tmp_path: Path) -> None:
        def fake_clone(cmd, **kwargs):
            if cmd[0] == "git" and cmd[1] == "clone":
                repo_dir = Path(cmd[-1])
                repo_dir.mkdir(parents=True, exist_ok=True)
                (repo_dir / "manifest.yml").write_text(VALID_MANIFEST)
                (repo_dir / "compose.yml").write_text(
                    "services:\n  web:\n    image: nginx\n"
                )
            return MagicMock(returncode=0, stdout="", stderr="")
        mock_run.side_effect = fake_clone

        run_add_git_project(
            "testapp", "git@github.com:org/testapp.git", paths, ref="main"
        )
        state = read_state(paths.project_deploy_state("testapp"))
        assert state.get("project_id") == "01TESTULID0000000000000000"

    def test_rejects_existing_project(self, paths: BoxPaths) -> None:
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text("project: testapp\n")

        result = run_add_git_project(
            "testapp", "git@github.com:org/testapp.git", paths
        )
        assert result == 1


class TestAddGitProjectLogging:
    def setup_method(self):
        _reset_logger()

    def teardown_method(self):
        _reset_logger()

    @patch("boxmunge.commands.add_git_project_cmd.subprocess.run")
    def test_uses_add_git_project_component(
        self, mock_run: MagicMock, paths: BoxPaths,
    ) -> None:
        """Component must match the CLI verb 'add-git-project' (not 'add-project')."""
        def fake_clone(cmd, **kwargs):
            if cmd[0] == "git" and cmd[1] == "clone":
                repo_dir = Path(cmd[-1])
                repo_dir.mkdir(parents=True, exist_ok=True)
                (repo_dir / "manifest.yml").write_text(VALID_MANIFEST)
                (repo_dir / "compose.yml").write_text(
                    "services:\n  web:\n    image: nginx\n"
                )
            return MagicMock(returncode=0, stdout="", stderr="")
        mock_run.side_effect = fake_clone

        run_add_git_project(
            "testapp", "git@github.com:org/testapp.git", paths, ref="main"
        )
        entries = [
            json.loads(line)
            for line in paths.log_file.read_text().strip().splitlines()
            if line
        ]
        components = {e.get("component") for e in entries}
        assert "add-git-project" in components
        assert "add-project" not in components
