# SPDX-License-Identifier: Apache-2.0
"""health compares the installed sshd drop-in with the release's copy."""
from pathlib import Path

from boxmunge.health_checks.sshd import check_sshd_hardening, shipped_dropin

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
