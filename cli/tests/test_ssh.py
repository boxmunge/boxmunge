"""Tests for SSH command building and execution."""

import pytest
from unittest.mock import patch, MagicMock

from boxmunge_cli.ssh import build_ssh_cmd, build_scp_cmd, run_ssh, run_scp


class TestBuildSshCmd:
    def test_basic_command(self) -> None:
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        cmd = build_ssh_cmd(config, "stage", "myapp")
        assert cmd == ["ssh", "-p", "922", "-o", "StrictHostKeyChecking=accept-new",
                       "deploy@box.example.com", "stage", "myapp"]

    def test_extra_args(self) -> None:
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        cmd = build_ssh_cmd(config, "prod-deploy", "myapp", "--dry-run")
        assert cmd == ["ssh", "-p", "922", "-o", "StrictHostKeyChecking=accept-new",
                       "deploy@box.example.com", "prod-deploy", "myapp", "--dry-run"]

    def test_custom_port_and_user(self) -> None:
        config = {"server": "10.0.0.1", "port": 2222, "user": "admin", "project": "myapp"}
        cmd = build_ssh_cmd(config, "status", "myapp")
        assert cmd == ["ssh", "-p", "2222", "-o", "StrictHostKeyChecking=accept-new",
                       "admin@10.0.0.1", "status", "myapp"]

    def test_no_project_arg(self) -> None:
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        cmd = build_ssh_cmd(config, "handshake")
        assert cmd == ["ssh", "-p", "922", "-o", "StrictHostKeyChecking=accept-new",
                       "deploy@box.example.com", "handshake"]


class TestBuildScpCmd:
    def test_basic_upload(self) -> None:
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        cmd = build_scp_cmd(config, "/tmp/myapp-2024.tar.gz")
        assert cmd == ["scp", "-O", "-P", "922", "-o", "StrictHostKeyChecking=accept-new",
                       "/tmp/myapp-2024.tar.gz", "deploy@box.example.com:"]


class TestRunSsh:
    @patch("boxmunge_cli.ssh.subprocess.run")
    def test_passes_args_as_list(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        code = run_ssh(config, "status", "myapp")
        call_args = mock_run.call_args[0][0]
        assert call_args == ["ssh", "-p", "922", "-o", "StrictHostKeyChecking=accept-new",
                              "deploy@box.example.com", "status", "myapp"]
        assert code == 0

    @patch("boxmunge_cli.ssh.subprocess.run")
    def test_shell_is_false(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        run_ssh(config, "status", "myapp")
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell", False) is False


class TestRunScp:
    @patch("boxmunge_cli.ssh.subprocess.run")
    def test_uploads_file(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        code = run_scp(config, "/tmp/bundle.tar.gz")
        call_args = mock_run.call_args[0][0]
        assert call_args == ["scp", "-O", "-P", "922", "-o", "StrictHostKeyChecking=accept-new",
                              "/tmp/bundle.tar.gz", "deploy@box.example.com:"]
        assert code == 0
