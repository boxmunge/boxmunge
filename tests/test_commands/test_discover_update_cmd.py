"""Tests for the internal _discover-update CLI command."""
import json
from unittest.mock import patch
import pytest


class TestCmdDiscoverUpdate:
    def test_emits_json_to_stdout(self, capsys):
        from boxmunge.commands.discover_update_cmd import cmd_discover_update
        with patch("boxmunge.commands.discover_update_cmd.discover_update") as m:
            m.return_value = {"action": "up_to_date", "current_version": "0.3.5"}
            with pytest.raises(SystemExit) as exc:
                cmd_discover_update(["--json"])
            assert exc.value.code == 0
        data = json.loads(capsys.readouterr().out)
        assert data["action"] == "up_to_date"

    def test_security_only_flag_passed_through(self, capsys):
        from boxmunge.commands.discover_update_cmd import cmd_discover_update
        with patch("boxmunge.commands.discover_update_cmd.discover_update") as m:
            m.return_value = {"action": "up_to_date", "current_version": "0.3.5"}
            with pytest.raises(SystemExit):
                cmd_discover_update(["--json", "--security-only"])
            assert m.call_args.kwargs.get("security_only") is True

    def test_requires_json_flag(self, capsys):
        from boxmunge.commands.discover_update_cmd import cmd_discover_update
        with pytest.raises(SystemExit) as exc:
            cmd_discover_update([])
        assert exc.value.code == 2
