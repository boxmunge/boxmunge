"""Tests for server-setup pre-flight checks."""

import pytest
from unittest.mock import patch, MagicMock

from boxmunge_cli.server_setup.preflight import (
    check_ssh_access,
    check_is_debian,
    check_privileges,
    check_not_installed,
    check_freshness,
    PreflightError,
)


def _mock_ssh(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


class TestCheckSshAccess:
    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_success(self, mock_run) -> None:
        mock_run.return_value = _mock_ssh(0, "ok")
        check_ssh_access("root", "box.example.com", 22)

    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_failure_raises(self, mock_run) -> None:
        mock_run.return_value = _mock_ssh(255, "", "Connection refused")
        with pytest.raises(PreflightError, match="SSH"):
            check_ssh_access("root", "box.example.com", 22)


class TestCheckIsDebian:
    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_debian_passes(self, mock_run) -> None:
        mock_run.return_value = _mock_ssh(0, 'ID=debian\nVERSION_ID="13"\n')
        check_is_debian("root", "box.example.com", 22)

    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_ubuntu_fails(self, mock_run) -> None:
        mock_run.return_value = _mock_ssh(0, 'ID=ubuntu\nVERSION_ID="24.04"\n')
        with pytest.raises(PreflightError, match="Debian"):
            check_is_debian("root", "box.example.com", 22)


class TestCheckPrivileges:
    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_direct_root(self, mock_run) -> None:
        mock_run.return_value = _mock_ssh(0, "0\n")
        needs_sudo = check_privileges("root", "box.example.com", 22)
        assert needs_sudo is False

    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_passwordless_sudo(self, mock_run) -> None:
        mock_run.side_effect = [
            _mock_ssh(0, "1000\n"),
            _mock_ssh(0, "0\n"),
        ]
        needs_sudo = check_privileges("admin", "box.example.com", 22)
        assert needs_sudo is True

    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_no_root_no_sudo_fails(self, mock_run) -> None:
        mock_run.side_effect = [
            _mock_ssh(0, "1000\n"),
            _mock_ssh(1, ""),
        ]
        with pytest.raises(PreflightError, match="sudo"):
            check_privileges("admin", "box.example.com", 22)


class TestCheckNotInstalled:
    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_clean_box_passes(self, mock_run) -> None:
        mock_run.return_value = _mock_ssh(1, "")
        check_not_installed("root", "box.example.com", 22, False)

    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_installed_fails(self, mock_run) -> None:
        mock_run.return_value = _mock_ssh(0, "")
        with pytest.raises(PreflightError, match="already installed"):
            check_not_installed("root", "box.example.com", 22, False)


class TestCheckFreshness:
    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_clean_box_returns_empty(self, mock_run) -> None:
        mock_run.return_value = _mock_ssh(0, "")
        warnings = check_freshness("root", "box.example.com", 22, False)
        assert warnings == []

    @patch("boxmunge_cli.server_setup.preflight.subprocess.run")
    def test_detects_extra_users(self, mock_run) -> None:
        mock_run.return_value = _mock_ssh(0, "webadmin\n")
        warnings = check_freshness("root", "box.example.com", 22, False)
        assert any("user" in w.lower() for w in warnings)
