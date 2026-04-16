"""Tests for project registry — allowlist of known project names."""

import pytest
from pathlib import Path

from boxmunge.paths import BoxPaths


class TestProjectRegistry:
    def test_load_empty_returns_empty_set(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import load_registered_projects
        result = load_registered_projects(paths)
        assert result == set()

    def test_add_project(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project, load_registered_projects
        add_project("myapp", paths)
        assert "myapp" in load_registered_projects(paths)

    def test_add_duplicate_is_idempotent(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project, load_registered_projects
        add_project("myapp", paths)
        add_project("myapp", paths)
        projects = load_registered_projects(paths)
        assert "myapp" in projects

    def test_remove_project(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project, remove_project, load_registered_projects
        add_project("myapp", paths)
        remove_project("myapp", paths)
        assert "myapp" not in load_registered_projects(paths)

    def test_remove_nonexistent_raises(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import remove_project
        with pytest.raises(ValueError, match="not registered"):
            remove_project("ghost", paths)

    def test_is_registered(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project, is_registered
        assert not is_registered("myapp", paths)
        add_project("myapp", paths)
        assert is_registered("myapp", paths)

    def test_validates_project_name(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project
        with pytest.raises(ValueError, match="Invalid project name"):
            add_project("BAD NAME!", paths)

    def test_auto_migrate_from_existing_dirs(self, paths: BoxPaths) -> None:
        """If projects.txt doesn't exist but project dirs do, auto-populate."""
        from boxmunge.project_registry import load_registered_projects
        for name in ["alpha", "beta"]:
            proj = paths.projects / name
            proj.mkdir(parents=True)
            (proj / "manifest.yml").write_text(f"project: {name}\n")
        result = load_registered_projects(paths)
        assert result == {"alpha", "beta"}
        assert (paths.config / "projects.txt").exists()

    def test_auto_migrate_ignores_pre_registered_dirs(self, paths: BoxPaths) -> None:
        """Dirs without manifest.yml are pre-registered (secrets-only), skip them."""
        from boxmunge.project_registry import load_registered_projects
        proj = paths.projects / "secrets-only"
        proj.mkdir(parents=True)
        result = load_registered_projects(paths)
        assert result == set()
