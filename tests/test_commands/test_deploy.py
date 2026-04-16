"""Tests for deploy command — state management and flow logic."""

import tarfile
from unittest.mock import patch

import pytest
from pathlib import Path

from boxmunge.commands.deploy import (
    record_deploy_state,
    prepare_caddy_config,
    prepare_compose_override,
    run_deploy,
)
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project
from boxmunge.state import read_state


MANIFEST = {
    "project": "myapp",
    "repo": "git@github.com:org/myapp.git",
    "ref": "main",
    "hosts": ["myapp.example.com"],
    "services": {
        "frontend": {
            "type": "frontend",
            "port": 3000,
            "routes": [{"path": "/"}],
        },
    },
    "backup": {"type": "none"},
    "deploy": {"snapshot_before_deploy": True},
    "env_files": ["project.env"],
}


class TestRecordDeployState:
    def test_records_current_ref(self, paths: BoxPaths) -> None:
        record_deploy_state(paths, "myapp", "abc123", None)
        state = read_state(paths.project_deploy_state("myapp"))
        assert state["current_ref"] == "abc123"
        assert "deployed_at" in state

    def test_pushes_previous_to_history(self, paths: BoxPaths) -> None:
        record_deploy_state(paths, "myapp", "ref1", "snap1.age")
        record_deploy_state(paths, "myapp", "ref2", "snap2.age")
        state = read_state(paths.project_deploy_state("myapp"))
        assert state["current_ref"] == "ref2"
        assert len(state["history"]) == 1
        assert state["history"][0]["ref"] == "ref1"


class TestPrepareCaddyConfig:
    def test_writes_caddy_site_config(self, paths: BoxPaths) -> None:
        prepare_caddy_config(paths, MANIFEST)
        site_conf = paths.project_caddy_site("myapp")
        assert site_conf.exists()
        content = site_conf.read_text()
        assert "myapp.example.com" in content
        assert "myapp-frontend:3000" in content

    def test_uses_override_if_present(self, paths: BoxPaths) -> None:
        override = paths.project_caddy_override("myapp")
        override.parent.mkdir(parents=True, exist_ok=True)
        override.write_text("custom caddy config\n")
        prepare_caddy_config(paths, MANIFEST)
        site_conf = paths.project_caddy_site("myapp")
        assert site_conf.read_text() == "custom caddy config\n"


class TestPrepareComposeOverride:
    def test_writes_override_file(self, paths: BoxPaths) -> None:
        project_dir = paths.project_dir("myapp")
        project_dir.mkdir(parents=True)
        prepare_compose_override(paths, MANIFEST)
        override = paths.project_compose_override("myapp")
        assert override.exists()
        assert "boxmunge-proxy" in override.read_text()


BUNDLE_MANIFEST = """\
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
backup:
  type: none
"""


def _place_deploy_bundle(paths, timestamp="2026-03-31T091500000000"):
    staging = paths.root / "tmp_staging" / "testapp"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.yml").write_text(BUNDLE_MANIFEST)
    (staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    filename = f"testapp-{timestamp}.tar.gz"
    bundle_path = paths.inbox / filename
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(staging, arcname="testapp")
    return bundle_path


class TestBundleSourceDeploy:
    @patch("boxmunge.commands.deploy.compose_up")
    @patch("boxmunge.commands.deploy.caddy_reload")
    def test_deploy_from_inbox(self, mock_reload, mock_up, paths):
        add_project("testapp", paths)
        _place_deploy_bundle(paths)
        result = run_deploy("testapp", paths)
        assert result == 0
        assert paths.project_dir("testapp").exists()
        assert (paths.project_dir("testapp") / "manifest.yml").exists()


class TestProjectRegistrationEnforcement:
    def test_rejects_unregistered_project(self, paths: BoxPaths, capsys) -> None:
        result = run_deploy("unregistered", paths)
        assert result == 1
        output = capsys.readouterr().out
        assert "not registered" in output
