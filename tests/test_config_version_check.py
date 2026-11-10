"""Tests for the version_check block of boxmunge.yml (the opt-out)."""

from pathlib import Path

import pytest

from boxmunge.config import ConfigError, load_config, version_check_enabled
from boxmunge.paths import BoxPaths

BASE = "hostname: box01.example.com\nadmin_email: admin@example.com\n"


def _load(tmp_root: Path, extra: str = "") -> dict:
    config_file = tmp_root / "config" / "boxmunge.yml"
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text(BASE + extra)
    return load_config(BoxPaths(root=tmp_root))


class TestVersionCheckConfig:
    def test_enabled_by_default(self, tmp_root: Path) -> None:
        cfg = _load(tmp_root)
        assert cfg["version_check"] == {"enabled": True}
        assert version_check_enabled(cfg) is True

    def test_can_be_turned_off(self, tmp_root: Path) -> None:
        assert version_check_enabled(_load(tmp_root, "version_check:\n  enabled: false\n")) is False

    @pytest.mark.parametrize("value", ['"false"', "0", "off-please", "null"])
    def test_non_boolean_is_an_error(self, tmp_root: Path, value: str) -> None:
        with pytest.raises(ConfigError, match="version_check.enabled"):
            _load(tmp_root, f"version_check:\n  enabled: {value}\n")

    def test_must_be_a_mapping(self, tmp_root: Path) -> None:
        with pytest.raises(ConfigError, match="'version_check' .* must be a mapping"):
            _load(tmp_root, "version_check: false\n")

    def test_unknown_key_is_an_error(self, tmp_root: Path) -> None:
        with pytest.raises(ConfigError, match="enable.*allowed: enabled"):
            _load(tmp_root, "version_check:\n  enable: false\n")

    def test_template_documents_the_key(self) -> None:
        template = Path(__file__).resolve().parents[1] / "config" / "boxmunge.yml.template"
        text = template.read_text()
        assert "version_check:" in text and "enabled: true" in text
