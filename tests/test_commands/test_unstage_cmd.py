"""Tests for boxmunge unstage command."""
from unittest.mock import patch

from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.staged_release import load_slot, new_meta, slot_dir, write_meta


class TestRunUnstage:
    def _setup_staging(self, paths):
        pdir = paths.project_dir("testapp")
        (pdir / "manifest.yml").parent.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text("project: testapp\n")
        (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        slot = slot_dir(paths, "testapp")
        (slot / "release").mkdir(parents=True)
        (slot / "compose.staging-base.yml").write_text("services: {}\n")
        (slot / "compose.boxmunge-staging.yml").write_text(
            "networks:\n  boxmunge-proxy:\n    external: true\n")
        write_meta(slot, new_meta("bundle", "testapp-v2", None))
        paths.project_staging_caddy_site("testapp").write_text(
            "staging.testapp.example.com {}\n")

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
    def test_drops_the_slot_and_its_compose_files(self, mock_down, mock_reload, paths):
        self._setup_staging(paths)
        run_unstage("testapp", paths)
        assert load_slot(paths, "testapp") is None
        assert not slot_dir(paths, "testapp").exists()

    @patch("boxmunge.commands.unstage_cmd.caddy_reload")
    @patch("boxmunge.commands.unstage_cmd.compose_down")
    def test_leaves_production_files(self, mock_down, mock_reload, paths):
        self._setup_staging(paths)
        run_unstage("testapp", paths)
        pdir = paths.project_dir("testapp")
        assert (pdir / "manifest.yml").read_text() == "project: testapp\n"
        assert (pdir / "compose.yml").exists()

    def test_fails_no_active_staging(self, paths):
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        result = run_unstage("testapp", paths)
        assert result == 1
