"""Tests for SSH key auto-detection."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from boxmunge_cli.server_setup.ssh_key import detect_ssh_key, SSHKeyError


class TestDetectSshKey:
    def test_returns_explicit_file_path(self, tmp_path: Path) -> None:
        key_file = tmp_path / "mykey.pub"
        key_file.write_text("ssh-ed25519 AAAA... user@host\n")
        result = detect_ssh_key(str(key_file))
        assert result.startswith("ssh-ed25519")

    def test_returns_explicit_key_string(self) -> None:
        key = "ssh-ed25519 AAAA... user@host"
        result = detect_ssh_key(key)
        assert result == key

    @patch("boxmunge_cli.server_setup.ssh_key.subprocess.run")
    def test_prefers_ed25519_from_agent(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="ssh-rsa AAAA... rsa@host\nssh-ed25519 BBBB... ed@host\n",
        )
        result = detect_ssh_key(None)
        assert result.startswith("ssh-ed25519")

    @patch("boxmunge_cli.server_setup.ssh_key.subprocess.run")
    def test_falls_back_to_rsa_from_agent(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="ssh-rsa AAAA... rsa@host\n",
        )
        result = detect_ssh_key(None)
        assert result.startswith("ssh-rsa")

    @patch("boxmunge_cli.server_setup.ssh_key.subprocess.run")
    def test_falls_back_to_file(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        key_file = tmp_path / ".ssh" / "id_ed25519.pub"
        key_file.parent.mkdir(parents=True)
        key_file.write_text("ssh-ed25519 CCCC... file@host\n")
        with patch("boxmunge_cli.server_setup.ssh_key.Path.home", return_value=tmp_path):
            result = detect_ssh_key(None)
        assert result.startswith("ssh-ed25519")

    @patch("boxmunge_cli.server_setup.ssh_key.subprocess.run")
    def test_raises_when_nothing_found(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        with patch("boxmunge_cli.server_setup.ssh_key.Path.home", return_value=tmp_path):
            with pytest.raises(SSHKeyError, match="No SSH public key found"):
                detect_ssh_key(None)
