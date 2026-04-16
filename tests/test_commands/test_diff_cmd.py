"""Tests for boxmunge diff command."""
import tarfile
import pytest
from pathlib import Path
from boxmunge.commands.diff_cmd import run_diff
from boxmunge.paths import BoxPaths

MANIFEST_V1 = """\
id: 01TEST
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

MANIFEST_V2 = """\
id: 01TEST
project: testapp
source: bundle
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
  api:
    port: 9000
    routes:
      - path: /api/*
"""

def _setup_project(paths, manifest=MANIFEST_V1):
    pdir = paths.project_dir("testapp")
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "manifest.yml").write_text(manifest)
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (pdir / "src").mkdir(exist_ok=True)
    (pdir / "src" / "app.py").write_text("print('hello')\n")

def _place_bundle(paths, manifest=MANIFEST_V2, timestamp="2026-03-31T091500000000"):
    staging = paths.root / "tmp_staging" / "testapp"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.yml").write_text(manifest)
    (staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n  api:\n    image: node\n")
    (staging / "src").mkdir(exist_ok=True)
    (staging / "src" / "app.py").write_text("print('hello v2')\n")
    (staging / "src" / "new_file.py").write_text("# new\n")
    bundle_path = paths.inbox / f"testapp-{timestamp}.tar.gz"
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(staging, arcname="testapp")
    return bundle_path

class TestRunDiff:
    def test_shows_changed_files(self, paths, capsys):
        _setup_project(paths)
        _place_bundle(paths)
        result = run_diff("testapp", paths)
        assert result == 0
        output = capsys.readouterr().out
        assert "manifest.yml" in output
        assert "changed" in output.lower()

    def test_shows_added_files(self, paths, capsys):
        _setup_project(paths)
        _place_bundle(paths)
        result = run_diff("testapp", paths)
        assert result == 0
        output = capsys.readouterr().out
        assert "added" in output.lower()

    def test_fails_no_project(self, paths):
        result = run_diff("nonexistent", paths)
        assert result == 1

    def test_fails_no_bundle(self, paths):
        _setup_project(paths)
        result = run_diff("testapp", paths)
        assert result == 1

    def test_identical_shows_no_changes(self, paths, capsys):
        _setup_project(paths)
        # Place a bundle identical to the current project
        staging = paths.root / "tmp_staging" / "testapp"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "manifest.yml").write_text(MANIFEST_V1)
        (staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        (staging / "src").mkdir(exist_ok=True)
        (staging / "src" / "app.py").write_text("print('hello')\n")
        bundle_path = paths.inbox / "testapp-2026-03-31T091500000000.tar.gz"
        with tarfile.open(bundle_path, "w:gz") as tar:
            tar.add(staging, arcname="testapp")
        result = run_diff("testapp", paths)
        assert result == 0
        output = capsys.readouterr().out
        assert "no changes" in output.lower() or "identical" in output.lower()
