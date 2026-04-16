"""Tests for boxmunge stage command."""
import tarfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from boxmunge.commands.stage_cmd import run_stage
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project
from boxmunge.state import read_state

VALID_MANIFEST = """\
id: 01TESTULID0000000000000000
project: testapp
source: bundle
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
"""

def _place_real_bundle(paths: BoxPaths, timestamp: str = "2026-03-31T091500000000") -> Path:
    staging = paths.root / "tmp_staging" / "testapp"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.yml").write_text(VALID_MANIFEST)
    (staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    filename = f"testapp-{timestamp}.tar.gz"
    bundle_path = paths.inbox / filename
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(staging, arcname="testapp")
    return bundle_path

class TestRunStage:
    @patch("boxmunge.commands.stage_cmd.caddy_reload")
    @patch("boxmunge.commands.stage_cmd.compose_up")
    def test_generates_staging_caddy_config(self, mock_up, mock_reload, paths):
        add_project("testapp", paths)
        _place_real_bundle(paths)
        run_stage("testapp", paths)
        staging_conf = paths.project_staging_caddy_site("testapp")
        assert staging_conf.exists()
        content = staging_conf.read_text()
        assert "staging.testapp.example.com" in content

    @patch("boxmunge.commands.stage_cmd.caddy_reload")
    @patch("boxmunge.commands.stage_cmd.compose_up")
    def test_generates_staging_compose_override(self, mock_up, mock_reload, paths):
        add_project("testapp", paths)
        _place_real_bundle(paths)
        run_stage("testapp", paths)
        override = paths.project_staging_compose_override("testapp")
        assert override.exists()
        content = override.read_text()
        assert "testapp-staging-web" in content

    @patch("boxmunge.commands.stage_cmd.caddy_reload")
    @patch("boxmunge.commands.stage_cmd.compose_up")
    def test_starts_staging_containers_with_project_name(self, mock_up, mock_reload, paths):
        add_project("testapp", paths)
        _place_real_bundle(paths)
        run_stage("testapp", paths)
        mock_up.assert_called_once()
        _, kwargs = mock_up.call_args
        assert kwargs.get("project_name") == "testapp-staging"

    @patch("boxmunge.commands.stage_cmd.caddy_reload")
    @patch("boxmunge.commands.stage_cmd.compose_up")
    def test_records_staging_state(self, mock_up, mock_reload, paths):
        add_project("testapp", paths)
        _place_real_bundle(paths)
        run_stage("testapp", paths)
        state = read_state(paths.project_staging_state("testapp"))
        assert state.get("active") is True

    @patch("boxmunge.commands.stage_cmd.caddy_reload")
    @patch("boxmunge.commands.stage_cmd.compose_up")
    def test_creates_project_dir_if_new(self, mock_up, mock_reload, paths):
        add_project("testapp", paths)
        _place_real_bundle(paths)
        assert not paths.project_dir("testapp").exists()
        run_stage("testapp", paths)
        assert paths.project_dir("testapp").exists()
        assert (paths.project_dir("testapp") / "manifest.yml").exists()

    def test_fails_no_bundle(self, paths):
        add_project("testapp", paths)
        result = run_stage("testapp", paths)
        assert result == 1

    @patch("boxmunge.commands.stage_cmd.caddy_reload")
    @patch("boxmunge.commands.stage_cmd.compose_up")
    def test_moves_bundle_to_consumed(self, mock_up, mock_reload, paths):
        add_project("testapp", paths)
        bundle = _place_real_bundle(paths)
        run_stage("testapp", paths)
        assert not bundle.exists()
        consumed = list(paths.inbox_consumed.iterdir())
        assert len(consumed) == 1

    @patch("boxmunge.commands.stage_cmd.caddy_reload")
    @patch("boxmunge.commands.stage_cmd.compose_up")
    def test_copies_smoke_scripts(self, mock_up, mock_reload, paths):
        add_project("testapp", paths)
        manifest_with_smoke = VALID_MANIFEST.replace(
            "    routes:\n      - path: /\n",
            "    routes:\n      - path: /\n    smoke: boxmunge-scripts/smoke.sh\n",
        )
        staging = paths.root / "tmp_staging_smoke" / "testapp"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "manifest.yml").write_text(manifest_with_smoke)
        (staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        scripts = staging / "boxmunge-scripts"
        scripts.mkdir()
        (scripts / "smoke.sh").write_text("#!/bin/bash\nexit 0\n")

        bundle_path = paths.inbox / "testapp-2026-03-31T091500000001.tar.gz"
        with tarfile.open(bundle_path, "w:gz") as tar:
            tar.add(staging, arcname="testapp")

        run_stage("testapp", paths)

        # Verify smoke.sh was copied into the project dir
        smoke_path = paths.project_dir("testapp") / "boxmunge-scripts" / "smoke.sh"
        assert smoke_path.exists()


class TestProjectRegistrationEnforcement:
    @patch("boxmunge.commands.stage_cmd.caddy_reload")
    @patch("boxmunge.commands.stage_cmd.compose_up")
    def test_rejects_unregistered_project(self, mock_up, mock_reload, paths, capsys):
        # Place bundle but DON'T register the project
        _place_real_bundle(paths)
        result = run_stage("testapp", paths)
        assert result == 1
        output = capsys.readouterr().out
        assert "not registered" in output

    @patch("boxmunge.commands.stage_cmd.caddy_reload")
    @patch("boxmunge.commands.stage_cmd.compose_up")
    def test_accepts_registered_project(self, mock_up, mock_reload, paths):
        add_project("testapp", paths)
        _place_real_bundle(paths)
        result = run_stage("testapp", paths)
        assert result == 0
