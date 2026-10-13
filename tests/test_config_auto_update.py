"""Tests for the auto_update block of boxmunge.yml."""

from pathlib import Path

import pytest

from boxmunge.config import ConfigError, auto_update_breakfix_enabled, load_config
from boxmunge.paths import BoxPaths

BASE = "hostname: box01.example.com\nadmin_email: admin@example.com\n"


def _load(tmp_root: Path, extra: str = "") -> dict:
    config_file = tmp_root / "config" / "boxmunge.yml"
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text(BASE + extra)
    return load_config(BoxPaths(root=tmp_root))


class TestAutoUpdateConfig:
    def test_breakfix_defaults_to_true(self, tmp_root: Path) -> None:
        cfg = _load(tmp_root)
        assert cfg["auto_update"] == {"breakfix": True}
        assert auto_update_breakfix_enabled(cfg) is True

    def test_breakfix_can_be_disabled(self, tmp_root: Path) -> None:
        cfg = _load(tmp_root, "auto_update:\n  breakfix: false\n")
        assert auto_update_breakfix_enabled(cfg) is False

    def test_breakfix_explicit_true(self, tmp_root: Path) -> None:
        cfg = _load(tmp_root, "auto_update:\n  breakfix: true\n")
        assert auto_update_breakfix_enabled(cfg) is True

    @pytest.mark.parametrize("value", ['"false"', "0", "1", "no-thanks", "null", "[]"])
    def test_non_boolean_breakfix_is_an_error(self, tmp_root: Path, value: str) -> None:
        with pytest.raises(ConfigError, match="auto_update.breakfix"):
            _load(tmp_root, f"auto_update:\n  breakfix: {value}\n")

    def test_auto_update_must_be_a_mapping(self, tmp_root: Path) -> None:
        with pytest.raises(ConfigError, match="auto_update"):
            _load(tmp_root, "auto_update: true\n")

    def test_unknown_auto_update_key_is_an_error(self, tmp_root: Path) -> None:
        with pytest.raises(ConfigError, match="breakfixes"):
            _load(tmp_root, "auto_update:\n  breakfixes: false\n")

    def test_template_documents_the_key(self) -> None:
        template = Path(__file__).resolve().parents[1] / "config" / "boxmunge.yml.template"
        text = template.read_text()
        assert "auto_update:" in text
        assert "breakfix: true" in text
