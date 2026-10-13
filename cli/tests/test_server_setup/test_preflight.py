"""Tests for server-setup pre-flight checks, against a fake ssh on PATH."""

from pathlib import Path

import pytest

from boxmunge_cli.server_setup.preflight import (
    PreflightError,
    check_freshness,
    check_is_debian,
    check_not_installed,
    check_privileges,
    check_ssh_access,
)
from boxmunge_cli.server_setup.remote import Target


@pytest.fixture
def target(tmp_path: Path) -> Target:
    return Target("root", "box.example.com", 22, tmp_path / "known_hosts")


@pytest.fixture
def admin(tmp_path: Path) -> Target:
    return Target("admin", "box.example.com", 22, tmp_path / "known_hosts")


class TestCheckSshAccess:
    def test_success(self, target, fake_remote) -> None:
        fake_remote.respond("ssh", "echo ok", stdout="ok\n")
        check_ssh_access(target)

    def test_failure_shows_ssh_error(self, target, fake_remote) -> None:
        fake_remote.respond("ssh", "echo ok", stderr="Connection refused", rc=255)
        with pytest.raises(PreflightError, match="Connection refused"):
            check_ssh_access(target)


class TestCheckIsDebian:
    def test_debian_passes(self, target, fake_remote) -> None:
        fake_remote.respond("ssh", "os-release", stdout='ID=debian\nVERSION_ID="13"\n')
        check_is_debian(target)

    def test_ubuntu_fails(self, target, fake_remote) -> None:
        fake_remote.respond("ssh", "os-release", stdout='ID=ubuntu\nVERSION_ID="24.04"\n')
        with pytest.raises(PreflightError, match="Debian"):
            check_is_debian(target)


class TestCheckPrivileges:
    def test_direct_root(self, target, fake_remote) -> None:
        fake_remote.respond("ssh", "id -u", stdout="0\n")
        assert check_privileges(target) is False

    def test_passwordless_sudo(self, admin, fake_remote) -> None:
        fake_remote.respond("ssh", "id -u", stdout="1000\n")
        fake_remote.respond("ssh", "sudo -n id -u", stdout="0\n")
        assert check_privileges(admin) is True

    def test_no_root_no_sudo_fails(self, admin, fake_remote) -> None:
        fake_remote.respond("ssh", "id -u", stdout="1000\n")
        fake_remote.respond("ssh", "sudo -n id -u", rc=1)
        with pytest.raises(PreflightError, match="sudo"):
            check_privileges(admin)


class TestCheckNotInstalled:
    def test_clean_box_passes(self, target, fake_remote) -> None:
        fake_remote.respond("ssh", "test -d /opt/boxmunge", rc=1)
        check_not_installed(target, False)

    def test_installed_fails(self, target, fake_remote) -> None:
        fake_remote.respond("ssh", "test -d /opt/boxmunge", rc=0)
        with pytest.raises(PreflightError, match="already installed"):
            check_not_installed(target, False)


class TestCheckFreshness:
    def test_clean_box_returns_empty(self, target, fake_remote) -> None:
        assert check_freshness(target, False) == []

    def test_detects_extra_users(self, target, fake_remote) -> None:
        fake_remote.respond("ssh", "/etc/passwd", stdout="webadmin\n")
        warnings = check_freshness(target, False)
        assert any("user" in w.lower() for w in warnings)
