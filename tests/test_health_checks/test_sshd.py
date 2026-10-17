# SPDX-License-Identifier: Apache-2.0
"""health compares the installed sshd drop-in with the release's copy, and asks
sshd for deploy's effective environment settings."""
import os
import subprocess
from pathlib import Path

import pytest

from boxmunge.health_checks.sshd import (
    check_sshd_deploy_env, check_sshd_hardening, shipped_dropin,
)

REPO = Path(__file__).resolve().parents[2]


def test_the_shipped_copy_is_the_one_install_sh_installs() -> None:
    assert shipped_dropin() == (REPO / "src/boxmunge/sshd/00-boxmunge.conf").read_text()
    script = (REPO / "bootstrap/sshd-hardening.sh").read_text()
    assert 'SOURCE="$(dirname "${BASH_SOURCE[0]}")/../src/boxmunge/sshd/00-boxmunge.conf"' in script
    assert 'DROPIN="/etc/ssh/sshd_config.d/00-boxmunge.conf"' in script


def test_installed_as_shipped_is_ok(tmp_path: Path) -> None:
    installed = tmp_path / "00-boxmunge.conf"
    installed.write_text(shipped_dropin())
    assert check_sshd_hardening(installed).status == "ok"


def test_missing_or_changed_is_an_error_naming_the_fix(tmp_path: Path) -> None:
    installed = tmp_path / "00-boxmunge.conf"
    missing = check_sshd_hardening(installed)
    installed.write_text(shipped_dropin().replace("PasswordAuthentication no",
                                                  "PasswordAuthentication yes"))
    changed = check_sshd_hardening(installed)
    for result, problem in ((missing, "is missing"), (changed, "differs")):
        assert result.status == "error"
        assert problem in result.detail and "boxmunge-install.sh" in result.detail


_PINNED = ("acceptenv LANG\nacceptenv LC_*\nacceptenv COLORTERM\nacceptenv NO_COLOR\n"
           "permituserenvironment no\nport 922\n")


def _sshd(stdout: str, returncode: int = 0):
    calls = []

    def run(argv, **_kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout, "no hostkeys")
    return run, calls


@pytest.fixture
def as_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)


def test_deploys_pinned_environment_is_ok(as_root) -> None:
    run, calls = _sshd(_PINNED)
    assert check_sshd_deploy_env(run).status == "ok"
    assert calls == [["/usr/sbin/sshd", "-T", "-C", "user=deploy,host=localhost,addr=127.0.0.1"]]


@pytest.mark.parametrize("stdout,problem", [
    (_PINNED + "acceptenv BASH_ENV\n", "BASH_ENV"),
    (_PINNED.replace("acceptenv NO_COLOR\n", ""), "not exactly"),
    (_PINNED.replace("permituserenvironment no", "permituserenvironment yes"),
     "PermitUserEnvironment"),
])
def test_a_widened_environment_is_an_error(as_root, stdout, problem) -> None:
    result = check_sshd_deploy_env(_sshd(stdout)[0])
    assert result.status == "error" and problem in result.detail
    assert "sshd -T -C user=deploy" in result.detail


def test_sshd_failing_is_an_error(as_root) -> None:
    result = check_sshd_deploy_env(_sshd("", returncode=255)[0])
    assert result.status == "error" and "no hostkeys" in result.detail


def test_without_root_it_is_skipped(monkeypatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    run, calls = _sshd(_PINNED)
    assert check_sshd_deploy_env(run).status == "skip" and calls == []
