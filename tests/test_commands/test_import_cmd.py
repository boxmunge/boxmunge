"""Tests for boxmunge import command."""

import tarfile
import pytest
from pathlib import Path
from unittest.mock import patch

from boxmunge.bundle import extract_bundle
from boxmunge.commands.import_cmd import run_import
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project


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


HOSTILE = "services:\n  web:\n    image: nginx\n    privileged: true\n"


def _make_bundle(tmp_path: Path, name: str = "testapp",
                 manifest: str = VALID_MANIFEST,
                 include_env: bool = True,
                 compose: str = "services:\n  web:\n    image: nginx\n") -> Path:
    """Create a valid project bundle tar.gz."""
    project_dir = tmp_path / "staging" / name
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(manifest)
    (project_dir / "compose.yml").write_text(compose)
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
        project_dir = extract_bundle(bundle, dest)
        assert project_dir.name == "testapp"
        assert (project_dir / "manifest.yml").exists()

    def test_rejects_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="not found"):
            extract_bundle(tmp_path / "nope.tar.gz", tmp_path)

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
            extract_bundle(bundle, dest)


def _deploy_patches():
    return (patch("boxmunge.commands.deploy.compose_up"),
            patch("boxmunge.commands.deploy.caddy_reload"))


class TestRunImport:
    def test_new_project_import(self, paths: BoxPaths, tmp_path: Path) -> None:
        add_project("testapp", paths)
        bundle = _make_bundle(tmp_path)
        up, reload = _deploy_patches()
        with up as mock_up, reload:
            result = run_import(str(bundle), paths, yes=True)
        assert result == 0
        assert (paths.project_dir("testapp") / "manifest.yml").exists()
        mock_up.assert_called_once()
        # The operator's file is copied, not moved; the filed copy is consumed.
        assert bundle.exists()
        assert len(list(paths.inbox_consumed.iterdir())) == 1

    def test_hostile_compose_never_reaches_disk(self, paths: BoxPaths,
                                                tmp_path: Path) -> None:
        """C-01: import goes through the same validate-before-install path."""
        add_project("testapp", paths)
        bundle = _make_bundle(tmp_path, compose=HOSTILE)
        up, reload = _deploy_patches()
        with up as mock_up, reload:
            result = run_import(str(bundle), paths, yes=True)
        assert result == 3
        mock_up.assert_not_called()
        assert not paths.project_dir("testapp").exists()

    def test_unregistered_project_rejected(self, paths: BoxPaths,
                                           tmp_path: Path, capsys) -> None:
        bundle = _make_bundle(tmp_path)
        assert run_import(str(bundle), paths, yes=True) == 1
        assert "not registered" in capsys.readouterr().err
        assert not paths.project_dir("testapp").exists()

    def test_invalid_manifest_rejects(self, paths: BoxPaths, tmp_path: Path) -> None:
        add_project("testapp", paths)
        bad_manifest = "project: testapp\nhosts: []\nservices: {}\n"
        bundle = _make_bundle(tmp_path, manifest=bad_manifest)
        result = run_import(str(bundle), paths, yes=True)
        assert result == 1
        # Project dir should NOT have been created
        assert not paths.project_dir("testapp").exists()

    def test_dry_run_doesnt_modify(self, paths: BoxPaths, tmp_path: Path) -> None:
        add_project("testapp", paths)
        bundle = _make_bundle(tmp_path)
        result = run_import(str(bundle), paths, yes=True, dry_run=True)
        assert result == 0
        assert not paths.project_dir("testapp").exists()
        assert not any(p.is_file() for p in paths.inbox.iterdir())

    def test_missing_compose_rejects(self, paths: BoxPaths, tmp_path: Path) -> None:
        add_project("testapp", paths)
        # Make a bundle without compose.yml
        project_dir = tmp_path / "staging" / "testapp"
        project_dir.mkdir(parents=True)
        (project_dir / "manifest.yml").write_text(VALID_MANIFEST)
        bundle = tmp_path / "testapp.tar.gz"
        with tarfile.open(bundle, "w:gz") as tar:
            tar.add(project_dir, arcname="testapp")
        result = run_import(str(bundle), paths, yes=True)
        assert result == 1
