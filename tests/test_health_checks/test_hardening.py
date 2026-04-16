"""Tests for hardening health checks (unit tests with mocked subprocess)."""

from unittest.mock import MagicMock, patch

import pytest

from boxmunge.health_checks.hardening import (
    check_aide_status,
    check_auditd,
    check_crowdsec,
    check_sysctl_hardening,
    check_systemd_timers,
    check_ufw,
    check_unattended_upgrades,
)


class TestCheckUFW:
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_active_and_correct(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "Status: active\n922/tcp ALLOW\n"
                "80/tcp ALLOW\n443/tcp ALLOW\n"
            ),
        )
        check = check_ufw(ssh_port=922)
        assert check.status == "ok"

    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_inactive(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="Status: inactive\n",
        )
        check = check_ufw(ssh_port=922)
        assert check.status == "error"

    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_not_installed(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError()
        check = check_ufw(ssh_port=922)
        assert check.status == "error"


class TestCheckCrowdSec:
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_running(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        check = check_crowdsec()
        assert check.status == "ok"

    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_not_running(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=3, stdout="")
        check = check_crowdsec()
        assert check.status == "warn"


class TestCheckAuditd:
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_running(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        check = check_auditd()
        assert check.status == "ok"

    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_not_running(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=3, stdout="")
        check = check_auditd()
        assert check.status == "warn"


class TestCheckSysctl:
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_all_correct(self, mock_run: MagicMock) -> None:
        def sysctl_side_effect(cmd, **kwargs):
            key = cmd[-1]
            values = {
                "net.ipv4.tcp_syncookies": "1",
                "kernel.unprivileged_bpf_disabled": "1",
                "kernel.kptr_restrict": "2",
                "fs.suid_dumpable": "0",
            }
            val = values.get(key, "0")
            return MagicMock(returncode=0, stdout=f"{val}\n")

        mock_run.side_effect = sysctl_side_effect
        check = check_sysctl_hardening()
        assert check.status == "ok"

    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_missing_setting(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="0\n",
        )
        check = check_sysctl_hardening()
        assert check.status == "warn"


class TestCheckUnattendedUpgrades:
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_active(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        check = check_unattended_upgrades()
        assert check.status == "ok"

    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_inactive(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=3)
        check = check_unattended_upgrades()
        assert check.status == "warn"


class TestCheckTimers:
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_all_active(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        check = check_systemd_timers()
        assert check.status == "ok"

    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_some_inactive(self, mock_run: MagicMock) -> None:
        def side_effect(cmd, **kwargs):
            timer = cmd[-1]
            if "backup" in timer:
                return MagicMock(returncode=3)
            return MagicMock(returncode=0)

        mock_run.side_effect = side_effect
        check = check_systemd_timers()
        assert check.status == "warn"
        assert "backup" in check.detail
