"""What shows the host config to a person says why it is wrong, rather
than showing a placeholder and nothing else."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.commands import help as help_cmd
from boxmunge.paths import BoxPaths
from boxmunge.tui.data import load_host_info

CONFIG = {"hostname": "box.example.com", "admin_email": "ops@example.com"}
ODD = {**CONFIG, "ssh_port": "922"}


@pytest.fixture
def box(paths: BoxPaths, monkeypatch) -> BoxPaths:
    paths.config_file.write_text(yaml.safe_dump(ODD))
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    return paths


class TestTheDashboard:
    def test_a_wrong_setting_is_shown_beside_the_hostname(self, box, fake_containers) -> None:
        info = load_host_info(box)
        assert info.hostname == "box.example.com"
        assert "'ssh_port'" in info.config_error

    def test_a_config_that_cannot_be_loaded_says_why(self, box, fake_containers) -> None:
        box.config_file.unlink()
        info = load_host_info(box)
        assert info.hostname == "unknown"
        assert "Config file not found" in info.config_error

    def test_a_sound_config_shows_nothing(self, box, fake_containers) -> None:
        box.config_file.write_text(yaml.safe_dump(CONFIG))
        assert load_host_info(box).config_error == ""


class TestHelp:
    def test_a_wrong_setting_is_said_and_help_is_still_shown(self, box, capsys) -> None:
        with pytest.raises(SystemExit) as shown:
            help_cmd.cmd_help([])
        assert shown.value.code == 0
        out = capsys.readouterr()
        assert "deploy@box.example.com:" in out.out
        assert "'ssh_port'" in out.err

    def test_a_config_that_cannot_be_loaded_says_why(self, box, capsys) -> None:
        box.config_file.unlink()
        with pytest.raises(SystemExit) as shown:
            help_cmd.cmd_help([])
        assert shown.value.code == 0
        out = capsys.readouterr()
        assert "deploy@<host>:" in out.out
        assert "Config file not found" in out.err

    def test_a_defect_in_the_loader_is_not_swallowed(self, box, monkeypatch) -> None:
        def broken(paths):
            raise RuntimeError("a bug")
        monkeypatch.setattr("boxmunge.config.read_config", broken)
        with pytest.raises(RuntimeError):
            help_cmd.cmd_help([])
