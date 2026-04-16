"""Tests for boxmunge validate command."""

import pytest
from pathlib import Path

from boxmunge.commands.validate import run_validate
from boxmunge.paths import BoxPaths


VALID_MANIFEST = """\
id: 01TESTULID0000000000000000
source: bundle
project: myapp
repo: git@github.com:org/myapp.git
ref: main
hosts:
  - myapp.example.com
services:
  frontend:
    type: frontend
    port: 3000
    routes:
      - path: /
    smoke: boxmunge-scripts/smoke.sh
backup:
  type: none
env_files:
  - project.env
"""


def _setup_project(paths: BoxPaths, name: str, manifest: str) -> None:
    project_dir = paths.project_dir(name)
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(manifest)
    (project_dir / "project.env").write_text("KEY=value\n")
    (project_dir / "compose.yml").write_text("services:\n  frontend:\n    image: nginx\n")


class TestValidate:
    def test_valid_project_returns_zero(self, paths: BoxPaths) -> None:
        _setup_project(paths, "myapp", VALID_MANIFEST)
        exit_code = run_validate("myapp", paths)
        assert exit_code == 0

    def test_missing_project_returns_one(self, paths: BoxPaths) -> None:
        exit_code = run_validate("nope", paths)
        assert exit_code == 1

    def test_invalid_manifest_returns_one(self, paths: BoxPaths) -> None:
        bad = VALID_MANIFEST.replace("hosts:\n  - myapp.example.com", "hosts: []")
        _setup_project(paths, "myapp", bad)
        exit_code = run_validate("myapp", paths)
        assert exit_code == 1

    def test_missing_env_file_warns(self, paths: BoxPaths, capsys) -> None:
        _setup_project(paths, "myapp", VALID_MANIFEST)
        (paths.project_dir("myapp") / "project.env").unlink()
        exit_code = run_validate("myapp", paths)
        captured = capsys.readouterr()
        assert exit_code == 0  # warning, not error
        assert "project.env" in captured.out.lower()

    def test_pre_registered_returns_error(self, paths: BoxPaths, capsys) -> None:
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "secrets.env").write_text("KEY=val\n")

        exit_code = run_validate("myapp", paths)
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "pre-registered" in captured.out
        assert "boxmunge deploy myapp" in captured.out
