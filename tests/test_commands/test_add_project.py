"""Tests for boxmunge add-project and list-projects commands."""

import pytest
from pathlib import Path

from boxmunge.commands.add_project import run_add_project
from boxmunge.commands.list_projects import run_list_projects
from boxmunge.paths import BoxPaths


def _setup_template(paths: BoxPaths) -> None:
    """Create a minimal project template."""
    tpl = paths.templates
    tpl.mkdir(parents=True, exist_ok=True)
    (tpl / "manifest.yml.template").write_text(
        "project: __PROJECT_NAME__\nrepo: git@github.com:org/__PROJECT_NAME__.git\n"
    )
    (tpl / "compose.yml.template").write_text(
        "services:\n  frontend:\n    image: __PROJECT_NAME__-frontend\n"
    )
    (tpl / "project.env.example").write_text("# __PROJECT_NAME__ env\n")
    scripts = tpl / "boxmunge-scripts"
    scripts.mkdir()
    (scripts / "smoke.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
    (tpl / "README.md").write_text("# __PROJECT_NAME__\n")


class TestAddProject:
    def test_creates_project_directory(self, paths: BoxPaths) -> None:
        _setup_template(paths)
        exit_code = run_add_project("newapp", paths)
        assert exit_code == 0
        assert (paths.project_dir("newapp")).is_dir()

    def test_substitutes_project_name(self, paths: BoxPaths) -> None:
        _setup_template(paths)
        run_add_project("coolapp", paths)
        manifest = (paths.project_dir("coolapp") / "manifest.yml").read_text()
        assert "coolapp" in manifest
        assert "__PROJECT_NAME__" not in manifest

    def test_smoke_script_is_executable(self, paths: BoxPaths) -> None:
        _setup_template(paths)
        run_add_project("newapp", paths)
        smoke = paths.project_dir("newapp") / "boxmunge-scripts" / "smoke.sh"
        assert smoke.exists()
        import os
        assert os.access(smoke, os.X_OK)

    def test_refuses_duplicate_project(self, paths: BoxPaths) -> None:
        _setup_template(paths)
        run_add_project("newapp", paths)
        exit_code = run_add_project("newapp", paths)
        assert exit_code == 1

    def test_creates_required_subdirectories(self, paths: BoxPaths) -> None:
        _setup_template(paths)
        run_add_project("newapp", paths)
        pdir = paths.project_dir("newapp")
        assert (pdir / "backups").is_dir()
        assert (pdir / "data").is_dir()
        assert (pdir / "boxmunge-scripts").is_dir()


class TestListProjects:
    def test_empty_projects_dir(self, paths: BoxPaths, capsys) -> None:
        exit_code = run_list_projects(paths)
        assert exit_code == 0
        assert "no projects" in capsys.readouterr().out.lower()

    def test_lists_existing_projects(self, paths: BoxPaths, capsys) -> None:
        _setup_template(paths)
        run_add_project("alpha", paths)
        run_add_project("beta", paths)
        exit_code = run_list_projects(paths)
        assert exit_code == 0
        output = capsys.readouterr().out
        assert "alpha" in output
        assert "beta" in output
