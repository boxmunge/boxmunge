"""Tests for boxmunge import command."""

import tarfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from boxmunge.commands.import_cmd import _extract_bundle, run_import
from boxmunge.paths import BoxPaths


VALID_MANIFEST = """\
id: 01TESTULID0000000000000000
source: bundle
project: testapp
repo: ""
ref: main
hosts:
  - testapp.example.com
services:
  web:
    type: frontend
    port: 8080
    routes:
      - path: /
backup:
  type: none
env_files:
  - project.env
"""


def _make_bundle(tmp_path: Path, name: str = "testapp",
                 manifest: str = VALID_MANIFEST,
                 include_env: bool = True) -> Path:
    """Create a valid project bundle tar.gz."""
    project_dir = tmp_path / "staging" / name
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(manifest)
    (project_dir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    if include_env:
        (project_dir / "project.env").write_text("KEY=value\n")
    else:
        (project_dir / "project.env.example").write_text("KEY=changeme\n")
    scripts = project_dir / "boxmunge-scripts"
    scripts.mkdir()
    (scripts / "smoke.sh").write_text("#!/bin/bash\nexit 0\n")

    bundle_path = tmp_path / f"{name}.tar.gz"
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(project_dir, arcname=name)
    return bundle_path


class TestExtractBundle:
    def test_extracts_valid_bundle(self, tmp_path: Path) -> None:
        bundle = _make_bundle(tmp_path)
        dest = tmp_path / "extract"
        dest.mkdir()
        project_dir = _extract_bundle(bundle, dest)
        assert project_dir.name == "testapp"
        assert (project_dir / "manifest.yml").exists()

    def test_rejects_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="not found"):
            _extract_bundle(tmp_path / "nope.tar.gz", tmp_path)

    def test_rejects_multiple_top_dirs(self, tmp_path: Path) -> None:
        staging = tmp_path / "staging"
        (staging / "app1").mkdir(parents=True)
        (staging / "app2").mkdir(parents=True)
        (staging / "app1" / "f").write_text("x")
        (staging / "app2" / "f").write_text("x")
        bundle = tmp_path / "multi.tar.gz"
        with tarfile.open(bundle, "w:gz") as tar:
            tar.add(staging / "app1", arcname="app1")
            tar.add(staging / "app2", arcname="app2")
        dest = tmp_path / "extract"
        dest.mkdir()
        with pytest.raises(ValueError, match="exactly one"):
            _extract_bundle(bundle, dest)


class TestRunImport:
    @patch("boxmunge.commands.import_cmd.run_deploy")
    def test_new_project_import(self, mock_deploy: MagicMock, paths: BoxPaths,
                                tmp_path: Path) -> None:
        bundle = _make_bundle(tmp_path)
        mock_deploy.return_value = 0
        result = run_import(str(bundle), paths, yes=True)
        assert result == 0
        assert paths.project_dir("testapp").exists()
        assert (paths.project_dir("testapp") / "manifest.yml").exists()
        mock_deploy.assert_called_once_with("testapp", paths)

    @patch("boxmunge.commands.import_cmd.run_deploy")
    def test_upgrade_preserves_env(self, mock_deploy: MagicMock, paths: BoxPaths,
                                   tmp_path: Path) -> None:
        # Set up existing project with a secret
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        (pdir / "project.env").write_text("SECRET=real_secret\n")

        # Bundle has a different project.env
        bundle = _make_bundle(tmp_path)
        mock_deploy.return_value = 0
        result = run_import(str(bundle), paths, yes=True)
        assert result == 0
        # Secret should be preserved, not overwritten
        assert (pdir / "project.env").read_text() == "SECRET=real_secret\n"

    @patch("boxmunge.commands.import_cmd.run_deploy")
    def test_new_project_copies_env_example(self, mock_deploy: MagicMock,
                                            paths: BoxPaths,
                                            tmp_path: Path) -> None:
        bundle = _make_bundle(tmp_path, include_env=False)
        mock_deploy.return_value = 0
        result = run_import(str(bundle), paths, yes=True)
        assert result == 0
        # project.env.example should have been copied to project.env
        assert (paths.project_dir("testapp") / "project.env").exists()

    def test_invalid_manifest_rejects(self, paths: BoxPaths, tmp_path: Path) -> None:
        bad_manifest = "project: testapp\nhosts: []\nservices: {}\n"
        bundle = _make_bundle(tmp_path, manifest=bad_manifest)
        result = run_import(str(bundle), paths, yes=True)
        assert result == 1
        # Project dir should NOT have been created
        assert not paths.project_dir("testapp").exists()

    def test_dry_run_doesnt_modify(self, paths: BoxPaths, tmp_path: Path) -> None:
        bundle = _make_bundle(tmp_path)
        result = run_import(str(bundle), paths, yes=True, dry_run=True)
        assert result == 0
        assert not paths.project_dir("testapp").exists()

    def test_missing_compose_rejects(self, paths: BoxPaths, tmp_path: Path) -> None:
        # Make a bundle without compose.yml
        project_dir = tmp_path / "staging" / "testapp"
        project_dir.mkdir(parents=True)
        (project_dir / "manifest.yml").write_text(VALID_MANIFEST)
        bundle = tmp_path / "testapp.tar.gz"
        with tarfile.open(bundle, "w:gz") as tar:
            tar.add(project_dir, arcname="testapp")
        result = run_import(str(bundle), paths, yes=True)
        assert result == 1
