"""Tests for boxmunge pause."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import yaml

from boxmunge.paths import BoxPaths


def _setup(tmp_path: Path) -> tuple[BoxPaths, str]:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects/myapp", "state/deploy",
              "state/health", "caddy/sites", "logs"]:
        (paths.root / d).mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    (paths.project_dir("myapp") / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": "myapp",
        "source": "bundle", "hosts": ["myapp.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (paths.project_dir("myapp") / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n"
    )
    paths.project_caddy_site("myapp").write_text("# original\n")
    return paths, "myapp"


class TestRunPause:
    @patch("boxmunge.commands.pause_cmd.compose_stop")
    @patch("boxmunge.commands.pause_cmd.caddy_reload")
    def test_writes_paused_state(self, _reload, _stop, tmp_path):
        from boxmunge.commands.pause_cmd import run_pause
        from boxmunge.pause import is_paused
        paths, name = _setup(tmp_path)
        rc = run_pause(name, paths, yes=True, reason="testing")
        assert rc == 0
        assert is_paused(name, paths)

    @patch("boxmunge.commands.pause_cmd.compose_stop")
    @patch("boxmunge.commands.pause_cmd.caddy_reload")
    def test_swaps_caddy_to_maintenance(self, _reload, _stop, tmp_path):
        from boxmunge.commands.pause_cmd import run_pause
        paths, name = _setup(tmp_path)
        run_pause(name, paths, yes=True)
        site_conf = paths.project_caddy_site(name).read_text()
        assert "/etc/caddy/maintenance" in site_conf
        assert "Retry-After" in site_conf

    @patch("boxmunge.commands.pause_cmd.compose_stop")
    @patch("boxmunge.commands.pause_cmd.caddy_reload")
    def test_calls_compose_stop(self, _reload, mock_stop, tmp_path):
        from boxmunge.commands.pause_cmd import run_pause
        paths, name = _setup(tmp_path)
        run_pause(name, paths, yes=True)
        mock_stop.assert_called_once()

    def test_refuses_unknown_project(self, tmp_path):
        from boxmunge.commands.pause_cmd import run_pause
        paths, _ = _setup(tmp_path)
        rc = run_pause("ghost", paths, yes=True)
        assert rc == 1

    @patch("boxmunge.commands.pause_cmd.compose_stop")
    @patch("boxmunge.commands.pause_cmd.caddy_reload")
    def test_refuses_already_paused(self, _reload, _stop, tmp_path):
        from boxmunge.commands.pause_cmd import run_pause
        paths, name = _setup(tmp_path)
        run_pause(name, paths, yes=True)
        rc = run_pause(name, paths, yes=True)
        assert rc == 1
