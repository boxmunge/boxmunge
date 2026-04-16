"""Tests for .boxmunge config parsing, validation, and discovery."""

import pytest
from pathlib import Path

from boxmunge_cli.config import (
    load_config,
    discover_config,
    validate_config,
    ConfigError,
)


class TestLoadConfig:
    def test_loads_valid_config(self, boxmunge_config: Path) -> None:
        cfg = load_config(boxmunge_config / ".boxmunge")
        assert cfg["server"] == "box.example.com"
        assert cfg["port"] == 922
        assert cfg["user"] == "deploy"
        assert cfg["project"] == "myapp"

    def test_defaults_port(self, tmp_path: Path) -> None:
        (tmp_path / ".boxmunge").write_text("server: box.example.com\nproject: myapp\n")
        cfg = load_config(tmp_path / ".boxmunge")
        assert cfg["port"] == 922

    def test_defaults_user(self, tmp_path: Path) -> None:
        (tmp_path / ".boxmunge").write_text("server: box.example.com\nproject: myapp\n")
        cfg = load_config(tmp_path / ".boxmunge")
        assert cfg["user"] == "deploy"

    def test_defaults_project_from_dir_name(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "my-app"
        project_dir.mkdir()
        (project_dir / ".boxmunge").write_text("server: box.example.com\n")
        cfg = load_config(project_dir / ".boxmunge")
        assert cfg["project"] == "my-app"

    def test_missing_server_raises(self, tmp_path: Path) -> None:
        (tmp_path / ".boxmunge").write_text("port: 922\n")
        with pytest.raises(ConfigError, match="server"):
            load_config(tmp_path / ".boxmunge")

    def test_file_not_found_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            load_config(tmp_path / ".boxmunge")


class TestValidateConfig:
    def test_valid_config_passes(self) -> None:
        validate_config({
            "server": "box.example.com",
            "port": 922, "user": "deploy", "project": "myapp",
        })

    def test_rejects_injection_in_server(self) -> None:
        with pytest.raises(ConfigError, match="server"):
            validate_config({
                "server": "; rm -rf /",
                "port": 922, "user": "deploy", "project": "myapp",
            })

    def test_rejects_backtick_in_server(self) -> None:
        with pytest.raises(ConfigError, match="server"):
            validate_config({
                "server": "`whoami`.evil.com",
                "port": 922, "user": "deploy", "project": "myapp",
            })

    def test_rejects_dollar_in_server(self) -> None:
        with pytest.raises(ConfigError, match="server"):
            validate_config({
                "server": "$HOME.evil.com",
                "port": 922, "user": "deploy", "project": "myapp",
            })

    def test_rejects_spaces_in_server(self) -> None:
        with pytest.raises(ConfigError, match="server"):
            validate_config({
                "server": "box .example.com",
                "port": 922, "user": "deploy", "project": "myapp",
            })

    def test_rejects_port_out_of_range(self) -> None:
        with pytest.raises(ConfigError, match="port"):
            validate_config({
                "server": "box.example.com", "port": 99999,
                "user": "deploy", "project": "myapp",
            })

    def test_rejects_port_zero(self) -> None:
        with pytest.raises(ConfigError, match="port"):
            validate_config({
                "server": "box.example.com", "port": 0,
                "user": "deploy", "project": "myapp",
            })

    def test_rejects_non_integer_port(self) -> None:
        with pytest.raises(ConfigError, match="port"):
            validate_config({
                "server": "box.example.com", "port": "abc",
                "user": "deploy", "project": "myapp",
            })

    def test_rejects_invalid_user(self) -> None:
        with pytest.raises(ConfigError, match="user"):
            validate_config({
                "server": "box.example.com", "port": 922,
                "user": "root; whoami", "project": "myapp",
            })

    def test_rejects_invalid_project(self) -> None:
        with pytest.raises(ConfigError, match="project"):
            validate_config({
                "server": "box.example.com", "port": 922,
                "user": "deploy", "project": "BAD NAME!",
            })

    def test_accepts_ip_address(self) -> None:
        validate_config({
            "server": "192.168.1.100",
            "port": 922, "user": "deploy", "project": "myapp",
        })

    def test_accepts_ipv6(self) -> None:
        validate_config({
            "server": "::1",
            "port": 922, "user": "deploy", "project": "myapp",
        })


class TestDiscoverConfig:
    def test_finds_in_current_dir(self, boxmunge_config: Path) -> None:
        path = discover_config(boxmunge_config)
        assert path == boxmunge_config / ".boxmunge"

    def test_finds_in_parent_dir(self, boxmunge_config: Path) -> None:
        subdir = boxmunge_config / "src" / "deep"
        subdir.mkdir(parents=True)
        path = discover_config(subdir)
        assert path == boxmunge_config / ".boxmunge"

    def test_raises_when_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="No .boxmunge found"):
            discover_config(tmp_path)
