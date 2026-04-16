"""Tests for the handshake command — version exchange for client compatibility."""

import json


class TestHandshake:
    def test_returns_valid_json(self, capsys) -> None:
        from boxmunge.commands.handshake_cmd import cmd_handshake
        cmd_handshake([])
        output = capsys.readouterr().out
        data = json.loads(output)
        assert "server_version" in data
        assert "min_client_version" in data
        assert "schema_version" in data

    def test_server_version_is_string(self, capsys) -> None:
        from boxmunge.commands.handshake_cmd import cmd_handshake
        cmd_handshake([])
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data["server_version"], str)

    def test_schema_version_is_int(self, capsys) -> None:
        from boxmunge.commands.handshake_cmd import cmd_handshake
        cmd_handshake([])
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data["schema_version"], int)

    def test_min_client_version_is_string(self, capsys) -> None:
        from boxmunge.commands.handshake_cmd import cmd_handshake
        cmd_handshake([])
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data["min_client_version"], str)
