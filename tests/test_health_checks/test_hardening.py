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
    # ufw status requires root, so the command-evaluation path only runs as
    # root. Simulate that here so these tests are deterministic regardless of
    # the (usually non-root) test/CI user.
    @patch("boxmunge.health_checks.hardening.os.geteuid", return_value=0)
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_active_and_correct(self, mock_run: MagicMock, _euid) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "Status: active\n922/tcp ALLOW\n"
                "80/tcp ALLOW\n443/tcp ALLOW\n"
            ),
        )
        check = check_ufw(ssh_port=922)
        assert check.status == "ok"

    @patch("boxmunge.health_checks.hardening.os.geteuid", return_value=0)
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_inactive(self, mock_run: MagicMock, _euid) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="Status: inactive\n",
        )
        check = check_ufw(ssh_port=922)
        assert check.status == "error"

    @patch("boxmunge.health_checks.hardening.os.geteuid", return_value=0)
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_not_installed(self, mock_run: MagicMock, _euid) -> None:
        mock_run.side_effect = FileNotFoundError()
        check = check_ufw(ssh_port=922)
        assert check.status == "error"

    @patch("boxmunge.health_checks.hardening.os.geteuid", return_value=0)
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_resolves_ufw_via_sbin_even_without_sbin_on_caller_path(
        self, mock_run: MagicMock, _euid, monkeypatch,
    ) -> None:
        """Regression: ufw lives in sbin. When the caller's PATH lacks sbin
        (e.g. the deploy restricted shell), the check must still find ufw by
        augmenting PATH — not report a false 'not installed' (which escalates
        health to exit 2)."""
        # Simulate the deploy shell's sbin-free PATH.
        monkeypatch.setenv(
            "PATH", "/usr/local/bin:/usr/bin:/bin:/opt/boxmunge/bin",
        )
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Status: active\n922/tcp\n80/tcp\n443/tcp\n",
        )
        check = check_ufw(ssh_port=922)

        # The subprocess must have been invoked with sbin appended to PATH.
        env = mock_run.call_args.kwargs["env"]
        path_dirs = env["PATH"].split(":")
        assert "/usr/sbin" in path_dirs
        assert "/sbin" in path_dirs
        assert check.status == "ok"

    @patch("boxmunge.health_checks.hardening.os.geteuid", return_value=1000)
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_non_root_skips_not_warns_or_errors(
        self, mock_run: MagicMock, _euid,
    ) -> None:
        """Regression: from a non-root caller (deploy restricted shell),
        `ufw status` fails with 'need to be root'. The check must report a
        neutral SKIP — not an error (which escalated health to exit 2 and
        looked like a firewall outage) and not even a warn (which still made
        health 'land in warnings by default' for a non-issue). The root
        health timer remains authoritative."""
        check = check_ufw(ssh_port=922)
        assert check.status == "skip"
        assert "root" in check.detail.lower()
        # Must not even attempt to run ufw as non-root.
        mock_run.assert_not_called()


class TestCheckAideNonRoot:
    @patch("pathlib.Path.exists")
    @patch("boxmunge.health_checks.hardening.subprocess.run")
    def test_permission_error_on_db_skips_not_crashes(
        self, mock_run: MagicMock, mock_exists: MagicMock,
    ) -> None:
        """Regression: AIDE's db dir is root-only; from the deploy shell
        Path.exists() raises PermissionError. The check must SKIP, not let
        the exception crash the whole health command."""
        mock_run.return_value = MagicMock(returncode=0, stdout="/usr/bin/aide\n")
        mock_exists.side_effect = PermissionError(13, "Permission denied")

        check = check_aide_status()
        assert check.status == "skip"
        assert "root" in check.detail.lower()


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
