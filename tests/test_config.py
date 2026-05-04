"""Tests for boxmunge.config — host configuration loading and validation."""

import pytest
from pathlib import Path

from boxmunge.config import load_config, ConfigError


def _write_config(path: Path, content: str) -> Path:
    config_file = path / "config" / "boxmunge.yml"
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text(content)
    return config_file


class TestLoadConfig:
    def test_loads_valid_config(self, tmp_root: Path) -> None:
        _write_config(tmp_root, """
hostname: box01.example.com
ssh_port: 922
admin_email: admin@example.com
pushover:
  user_key: "utest"
  app_token: "atest"
backup_remote: "b2:bucket/backups"
health:
  check_interval_minutes: 5
  alert_threshold: 3
reboot:
  auto_reboot: true
  reboot_window: "04:00"
logging:
  docker_max_size: "50m"
  docker_max_file: 5
""")
        from boxmunge.paths import BoxPaths
        cfg = load_config(BoxPaths(root=tmp_root))
        assert cfg["hostname"] == "box01.example.com"
        assert cfg["ssh_port"] == 922
        assert cfg["pushover"]["user_key"] == "utest"
        assert cfg["health"]["alert_threshold"] == 3

    def test_missing_config_file_raises(self, tmp_root: Path) -> None:
        from boxmunge.paths import BoxPaths
        with pytest.raises(ConfigError, match="not found"):
            load_config(BoxPaths(root=tmp_root))

    def test_missing_required_field_raises(self, tmp_root: Path) -> None:
        _write_config(tmp_root, "ssh_port: 922\n")
        from boxmunge.paths import BoxPaths
        with pytest.raises(ConfigError, match="hostname"):
            load_config(BoxPaths(root=tmp_root))

    def test_defaults_applied(self, tmp_root: Path) -> None:
        _write_config(tmp_root, """
hostname: box01.example.com
admin_email: admin@example.com
""")
        from boxmunge.paths import BoxPaths
        cfg = load_config(BoxPaths(root=tmp_root))
        assert cfg["ssh_port"] == 922
        assert cfg["health"]["check_interval_minutes"] == 5
        assert cfg["health"]["alert_threshold"] == 3


class TestContainerUpdatesDefaults:
    def test_container_updates_default_block(self, tmp_path):
        from boxmunge.paths import BoxPaths
        from boxmunge.config import load_config
        paths = BoxPaths(root=tmp_path / "bm")
        paths.config.mkdir(parents=True)
        paths.config_file.write_text("hostname: t\nadmin_email: t@t\n")
        cfg = load_config(paths)
        assert cfg["container_updates"]["enabled"] is True
        assert cfg["container_updates"]["strategy"] == "leave_broken"

    def test_container_updates_user_override(self, tmp_path):
        from boxmunge.paths import BoxPaths
        from boxmunge.config import load_config
        paths = BoxPaths(root=tmp_path / "bm")
        paths.config.mkdir(parents=True)
        paths.config_file.write_text(
            "hostname: t\nadmin_email: t@t\n"
            "container_updates:\n"
            "  strategy: rollback_to_previous\n"
        )
        cfg = load_config(paths)
        assert cfg["container_updates"]["strategy"] == "rollback_to_previous"
        # Other defaults preserved (deep merge)
        assert cfg["container_updates"]["enabled"] is True
