"""The steps init-host.sh sources from sshd.sh, unattended.sh and summary.sh,
run on a real Debian 13 userland the way init-host runs them."""
from __future__ import annotations

import pytest

from tests.integration.conftest import skip_no_docker
from tests.integration.test_bootstrap_trixie import _STUB_SYSTEMCTL, _run_on_trixie

pytestmark = [pytest.mark.integration, skip_no_docker]


def test_sshd_sh_leaves_a_valid_hardened_config_on_trixie() -> None:
    result = _run_on_trixie(
        _STUB_SYSTEMCTL
        + "apt-get install -y -qq openssh-server >/dev/null\n"
        "ssh-keygen -A >/dev/null\n"
        "set -e\n"
        "SSH_PORT=922 DEPLOY_USER=deploy; . /bootstrap/sshd.sh\n"
        "sshd -t && echo valid\n"
        "sshd -T | grep -E '^(port|allowusers|passwordauthentication|permitrootlogin|"
        "allowtcpforwarding|x11forwarding) ' | sort\n"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "valid" in result.stdout
    for line in ("port 922", "allowusers deploy", "allowusers supervisor",
                 "passwordauthentication no", "permitrootlogin no",
                 "allowtcpforwarding no", "x11forwarding no"):
        assert line in result.stdout


def test_unattended_sh_installs_the_debian_config_on_trixie() -> None:
    result = _run_on_trixie(
        _STUB_SYSTEMCTL
        + "set -e\n"
        "ID=debian REBOOT_WINDOW=03:30; . /bootstrap/unattended.sh\n"
        "cmp /bootstrap/50unattended-upgrades-debian /etc/apt/apt.conf.d/50unattended-upgrades"
        " && echo same\n"
        "cat /etc/apt/apt.conf.d/20auto-upgrades\n"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "same" in result.stdout
    assert 'Automatic-Reboot-Time "03:30"' in result.stdout


def test_summary_sh_reports_the_box_and_refuses_a_missing_value() -> None:
    values = ("HOSTNAME_ARG=box.example.com SSH_PORT=922 DEPLOY_USER=deploy "
              "BOXMUNGE_ROOT=/opt/boxmunge CADDY_STATUS=running BACKUP_PUBKEY=age1test")
    result = _run_on_trixie(
        f"( {values} USERNS_OFFSET=1048576; . /bootstrap/summary.sh )\n"
        f"( {values}; . /bootstrap/summary.sh ) > /dev/null 2>&1 || echo missing=refused\n"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Hostname   : box.example.com" in result.stdout
    assert "container uid N is host uid 1048576+N" in result.stdout
    assert "ssh -p 922 supervisor@box.example.com" in result.stdout
    assert "missing=refused" in result.stdout
