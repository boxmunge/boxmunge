"""Tests for boxmunge.commands.deploy."""

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
