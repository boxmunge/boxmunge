"""Tests for boxmunge unstage command."""
import pytest
from unittest.mock import patch, MagicMock
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.paths import BoxPaths
from boxmunge.state import write_state, read_state

class TestRunUnstage:
    def _setup_staging(self, paths):
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text("project: testapp\n")
        (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        paths.project_staging_compose_override("testapp").write_text(
            "networks:\n  boxmunge-proxy:\n    external: true\n")
        paths.project_staging_caddy_site("testapp").write_text(
            "staging.testapp.example.com {}\n")
        write_state(paths.project_staging_state("testapp"), {"active": True})

    @patch("boxmunge.commands.unstage_cmd.caddy_reload")
    @patch("boxmunge.commands.unstage_cmd.compose_down")
    def test_tears_down_staging(self, mock_down, mock_reload, paths):
        self._setup_staging(paths)
        result = run_unstage("testapp", paths)
        assert result == 0
        mock_down.assert_called_once()
        _, kwargs = mock_down.call_args
        assert kwargs.get("project_name") == "testapp-staging"

    @patch("boxmunge.commands.unstage_cmd.caddy_reload")
    @patch("boxmunge.commands.unstage_cmd.compose_down")
    def test_removes_staging_caddy_config(self, mock_down, mock_reload, paths):
        self._setup_staging(paths)
        run_unstage("testapp", paths)
        assert not paths.project_staging_caddy_site("testapp").exists()

    @patch("boxmunge.commands.unstage_cmd.caddy_reload")
    @patch("boxmunge.commands.unstage_cmd.compose_down")
    def test_removes_staging_compose_override(self, mock_down, mock_reload, paths):
        self._setup_staging(paths)
        run_unstage("testapp", paths)
        assert not paths.project_staging_compose_override("testapp").exists()

    @patch("boxmunge.commands.unstage_cmd.caddy_reload")
    @patch("boxmunge.commands.unstage_cmd.compose_down")
    def test_clears_staging_state(self, mock_down, mock_reload, paths):
        self._setup_staging(paths)
        run_unstage("testapp", paths)
        state = read_state(paths.project_staging_state("testapp"))
        assert state.get("active") is not True

    def test_fails_no_active_staging(self, paths):
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        result = run_unstage("testapp", paths)
        assert result == 1
