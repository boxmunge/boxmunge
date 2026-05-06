"""Tests for deploy command — state management and flow logic."""

import tarfile
from unittest.mock import patch

import pytest
from pathlib import Path

from boxmunge.commands.deploy import (
    cmd_deploy,
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
        captured = capsys.readouterr()
        assert "not registered" in captured.err


class TestRefusesPaused:
    def test_refuses_paused_project(self, paths: BoxPaths, capsys) -> None:
        from boxmunge.pause import write_paused_state
        add_project("myapp", paths)
        write_paused_state("myapp", paths)
        rc = run_deploy("myapp", paths)
        assert rc == 1
        err = capsys.readouterr().err
        assert "paused" in err.lower()


class TestRejectsUnknownArgs:
    """Audit H-1b: silent-drop for unknown args was a footgun. Reject loudly."""

    def test_unknown_flag_returns_2(self, capfd) -> None:
        with pytest.raises(SystemExit) as exc:
            cmd_deploy(["myapp", "--not-a-flag"])
        assert exc.value.code == 2
        captured = capfd.readouterr()
        assert "ERROR" in captured.err
        assert "--not-a-flag" in captured.err


class TestDeployComposeRejectionExit3:
    """Audit H-N2: hardening rejection returns exit code 3, not 1."""

    def test_hostile_compose_returns_3(self, paths: BoxPaths) -> None:
        add_project("testapp", paths)
        _place_deploy_bundle(paths)
        # Replace just-extracted compose.yml after first deploy run? Easier:
        # mock validate_user_compose to raise ComposeSecurityError directly.
        from boxmunge.compose_validate import ComposeSecurityError
        with patch(
            "boxmunge.commands.deploy.validate_user_compose",
            side_effect=ComposeSecurityError("simulated hostile key: privileged"),
        ):
            with patch("boxmunge.commands.deploy.compose_up"):
                with patch("boxmunge.commands.deploy.caddy_reload"):
                    rc = run_deploy("testapp", paths)
        assert rc == 3
