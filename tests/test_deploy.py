"""Tests for boxmunge.commands.deploy."""

import io
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.deploy import run_deploy, prepare_compose_override
from boxmunge.paths import BoxPaths


BUNDLE_MANIFEST = """\
id: 01TEST00000000000000000000
project: testapp
source: bundle
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
    smoke: boxmunge-scripts/smoke.sh
backup:
  type: none
"""


class TestDeployEnvFiles:
    @patch("boxmunge.commands.deploy.compose_up")
    @patch("boxmunge.commands.deploy.caddy_reload")
    def test_compose_override_includes_env_files(self, mock_reload, mock_up, paths):
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(BUNDLE_MANIFEST)
        (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        (pdir / "secrets.env").write_text("SECRET=value\n")
        paths.host_secrets.write_text("HOST_TOKEN=abc\n")

        run_deploy("testapp", paths)

        override = (pdir / "compose.boxmunge.yml").read_text()
        assert "secrets.env" in override


class TestComposeOverrideEmitsOffWarning:
    def test_warning_printed_when_off(self, tmp_path, monkeypatch) -> None:
        # Build a paths-like with a real project_compose_override target.
        from boxmunge.paths import BoxPaths
        proj = tmp_path / "projects" / "demo"
        proj.mkdir(parents=True)
        (proj / "project.env").write_text("X=1\n")

        # Monkey-patch BoxPaths to point at tmp_path.
        monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
        paths = BoxPaths()
        paths.host_secrets = tmp_path / "host_secrets.env"  # absent
        paths.project_compose_override = lambda name: proj / "compose.boxmunge.yml"
        paths.project_dir = lambda name: proj
        paths.project_secrets = lambda name: proj / "secrets.env"

        manifest = {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "security": {"profile": "off", "reason": "test"},
            "services": {
                "web": {"port": 3000, "routes": [{"path": "/"}]},
            },
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            prepare_compose_override(paths, manifest)
        out = buf.getvalue()
        assert "SECURITY OFF" in out
        assert "demo/web" in out
        assert "test" in out

    def test_no_warning_when_default(self, tmp_path, monkeypatch) -> None:
        from boxmunge.paths import BoxPaths
        proj = tmp_path / "projects" / "demo"
        proj.mkdir(parents=True)
        monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
        paths = BoxPaths()
        paths.host_secrets = tmp_path / "host_secrets.env"
        paths.project_compose_override = lambda name: proj / "compose.boxmunge.yml"
        paths.project_dir = lambda name: proj
        paths.project_secrets = lambda name: proj / "secrets.env"

        manifest = {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            prepare_compose_override(paths, manifest)
        assert "SECURITY OFF" not in buf.getvalue()

    def test_component_param_threads_through(self, tmp_path, monkeypatch) -> None:
        """`component=` is forwarded to warn_off_services so upgrade/resume
        don't get misattributed as 'deploy' in the structured log."""
        from boxmunge.paths import BoxPaths
        proj = tmp_path / "projects" / "demo"
        proj.mkdir(parents=True)
        monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
        paths = BoxPaths()
        paths.host_secrets = tmp_path / "host_secrets.env"
        paths.project_compose_override = lambda name: proj / "compose.boxmunge.yml"
        paths.project_dir = lambda name: proj
        paths.project_secrets = lambda name: proj / "secrets.env"

        manifest = {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "security": {"profile": "off", "reason": "test"},
            "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
        }

        captured: list[str] = []

        def fake_warn(p, m, *, component):
            captured.append(component)

        monkeypatch.setattr(
            "boxmunge.compose.warn_off_services", fake_warn,
        )

        # Default
        prepare_compose_override(paths, manifest)
        # Explicit override (mirrors upgrade_cmd / resume_cmd call sites)
        prepare_compose_override(paths, manifest, component="upgrade")
        prepare_compose_override(paths, manifest, component="resume")

        assert captured == ["deploy", "upgrade", "resume"]
