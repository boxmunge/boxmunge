"""Tests for the client-side version handshake."""

import json
import pytest
from unittest.mock import patch, MagicMock

from boxmunge_cli.handshake import check_server_compatibility, HandshakeError


VALID_RESPONSE = json.dumps({
    "server_version": "0.2.0",
    "min_client_version": "0.1.0",
    "schema_version": 1,
})


class TestCheckServerCompatibility:
    @patch("boxmunge_cli.handshake.subprocess.run")
    def test_passes_when_compatible(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout=VALID_RESPONSE)
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        check_server_compatibility(config)  # should not raise

    @patch("boxmunge_cli.handshake.subprocess.run")
    def test_rejects_when_client_too_old(self, mock_run: MagicMock) -> None:
        response = json.dumps({
            "server_version": "1.0.0",
            "min_client_version": "99.0.0",
            "schema_version": 1,
        })
        mock_run.return_value = MagicMock(returncode=0, stdout=response)
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        with pytest.raises(HandshakeError, match="upgrade"):
            check_server_compatibility(config)

    @patch("boxmunge_cli.handshake.subprocess.run")
    def test_warns_when_server_old(self, mock_run: MagicMock, capsys) -> None:
        response = json.dumps({
            "server_version": "0.0.1",
            "min_client_version": "0.1.0",
            "schema_version": 1,
        })
        mock_run.return_value = MagicMock(returncode=0, stdout=response)
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        check_server_compatibility(config)  # should not raise
        output = capsys.readouterr().err
        assert "WARNING" in output or "old" in output.lower()

    @patch("boxmunge_cli.handshake.subprocess.run")
    def test_handles_ssh_failure(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=255, stdout="")
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        with pytest.raises(HandshakeError, match="[Ff]ailed|connect"):
            check_server_compatibility(config)

    @patch("boxmunge_cli.handshake.subprocess.run")
    def test_handles_malformed_json(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="not json")
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        with pytest.raises(HandshakeError, match="[Mm]alformed|[Ii]nvalid"):
            check_server_compatibility(config)
