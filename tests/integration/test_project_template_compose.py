# SPDX-License-Identifier: Apache-2.0
"""Integration: templates/project/compose.yml.template passes the real compose
validation (`docker compose config` plus boxmunge's rules) for the services
the manifest template declares."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from boxmunge.compose_validate import validate_user_compose
from boxmunge.paths import BoxPaths

pytestmark = pytest.mark.integration

TEMPLATES = Path(__file__).resolve().parents[2] / "templates" / "project"
PROJECT = "tplcompose"


def _render(src: Path, dest: Path) -> None:
    dest.write_text(src.read_text().replace("__PROJECT_NAME__", PROJECT))


def test_compose_template_validates(tmp_path: Path) -> None:
    paths = BoxPaths(root=tmp_path / "bm")
    project_dir = paths.project_dir(PROJECT)
    project_dir.mkdir(parents=True)
    _render(TEMPLATES / "compose.yml.template", project_dir / "compose.yml")
    _render(TEMPLATES / "project.env.example", project_dir / "project.env")
    shutil.copytree(TEMPLATES / "boxmunge-scripts", project_dir / "boxmunge-scripts")
    manifest = yaml.safe_load((TEMPLATES / "manifest.yml.template").read_text()
                              .replace("__PROJECT_NAME__", PROJECT))

    validate_user_compose(project_dir / "compose.yml", paths, project_name=PROJECT,
                          manifest_services=manifest["services"])
