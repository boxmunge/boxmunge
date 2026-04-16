"""Tests for boxmunge promote command."""
import pytest
from unittest.mock import patch, MagicMock
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.paths import BoxPaths
from boxmunge.state import write_state

VALID_MANIFEST = """\
project: testapp
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
backup:
  type: none
"""

class TestRunPromote:
    def _setup_staged(self, paths):
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        paths.project_staging_compose_override("testapp").write_text(
            "networks:\n  boxmunge-proxy:\n    external: true\n")
        paths.project_staging_caddy_site("testapp").write_text(
            "staging.testapp.example.com {}\n")
        write_state(paths.project_staging_state("testapp"), {"active": True})

    @patch("boxmunge.commands.promote_cmd.run_deploy")
    @patch("boxmunge.commands.promote_cmd.run_unstage")
    def test_unstages_then_deploys(self, mock_unstage, mock_deploy, paths):
        self._setup_staged(paths)
        mock_unstage.return_value = 0
        mock_deploy.return_value = 0
        result = run_promote("testapp", paths)
        assert result == 0
        mock_unstage.assert_called_once()
        mock_deploy.assert_called_once()

    def test_fails_no_active_staging(self, paths):
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        result = run_promote("testapp", paths)
        assert result == 1

    @patch("boxmunge.commands.promote_cmd.run_deploy")
    @patch("boxmunge.commands.promote_cmd.run_unstage")
    def test_deploys_to_production(self, mock_unstage, mock_deploy, paths):
        self._setup_staged(paths)
        mock_unstage.return_value = 0
        mock_deploy.return_value = 0
        run_promote("testapp", paths)
        deploy_call = mock_deploy.call_args
        assert deploy_call[0][0] == "testapp"
