"""Tests for boxmunge init command."""

import pytest
import yaml
from pathlib import Path

from boxmunge_cli.init_cmd import run_init


class TestRunInit:
    def test_creates_boxmunge_config(self, tmp_path: Path) -> None:
        result = run_init(tmp_path, server="box.example.com", project="myapp")
        assert result == 0
        cfg = yaml.safe_load((tmp_path / ".boxmunge").read_text())
        assert cfg["server"] == "box.example.com"
        assert cfg["port"] == 922
        assert cfg["user"] == "deploy"

    def test_project_defaults_to_dir_name(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "my-cool-app"
        project_dir.mkdir()
        run_init(project_dir, server="box.example.com")
        cfg = yaml.safe_load((project_dir / ".boxmunge").read_text())
        assert cfg["project"] == "my-cool-app"

    def test_custom_port_user_project(self, tmp_path: Path) -> None:
        run_init(tmp_path, server="10.0.0.1", port=2222, user="admin", project="myapp")
        cfg = yaml.safe_load((tmp_path / ".boxmunge").read_text())
        assert cfg["port"] == 2222
        assert cfg["user"] == "admin"
        assert cfg["project"] == "myapp"

    def test_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        (tmp_path / ".boxmunge").write_text("server: old\n")
        result = run_init(tmp_path, server="new.example.com")
        assert result == 1
        assert "old" in (tmp_path / ".boxmunge").read_text()

    def test_force_overwrites(self, tmp_path: Path) -> None:
        (tmp_path / ".boxmunge").write_text("server: old\n")
        result = run_init(tmp_path, server="new.example.com", force=True, project="myapp")
        assert result == 0
        cfg = yaml.safe_load((tmp_path / ".boxmunge").read_text())
        assert cfg["server"] == "new.example.com"

    def test_invalid_project_name_fails(self, tmp_path: Path) -> None:
        result = run_init(tmp_path, server="box.example.com", project="BAD!")
        assert result == 1

    def test_scaffolds_when_no_manifest(self, tmp_path: Path) -> None:
        run_init(tmp_path, server="box.example.com", project="myapp")
        assert (tmp_path / "manifest.yml").exists()
        assert (tmp_path / "compose.yml").exists()
        assert (tmp_path / "boxmunge-scripts" / "smoke.sh").exists()
        assert (tmp_path / ".env.example").exists()

    def test_skips_scaffold_when_manifest_exists(self, tmp_path: Path) -> None:
        (tmp_path / "manifest.yml").write_text("project: existing\n")
        run_init(tmp_path, server="box.example.com", project="myapp")
        content = (tmp_path / "manifest.yml").read_text()
        assert "existing" in content

    def test_no_scaffold_flag(self, tmp_path: Path) -> None:
        run_init(tmp_path, server="box.example.com", project="myapp", no_scaffold=True)
        assert (tmp_path / ".boxmunge").exists()
        assert not (tmp_path / "manifest.yml").exists()

    def test_force_scaffold_creates_missing_only(self, tmp_path: Path) -> None:
        (tmp_path / "manifest.yml").write_text("project: existing\n")
        run_init(tmp_path, server="box.example.com", project="myapp", force_scaffold=True)
        assert "existing" in (tmp_path / "manifest.yml").read_text()
        assert (tmp_path / "compose.yml").exists()

    def test_scaffold_substitutes_project_name(self, tmp_path: Path) -> None:
        run_init(tmp_path, server="box.example.com", project="coolapp")
        manifest = (tmp_path / "manifest.yml").read_text()
        assert "coolapp" in manifest

    def test_scaffold_has_todo_markers(self, tmp_path: Path) -> None:
        run_init(tmp_path, server="box.example.com", project="myapp")
        manifest = (tmp_path / "manifest.yml").read_text()
        assert "TODO" in manifest
