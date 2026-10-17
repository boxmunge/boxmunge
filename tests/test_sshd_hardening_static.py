"""boxmunge's sshd drop-in sorts first, closes logins and forwarding, and both
a fresh bootstrap and every install/upgrade apply it (the trixie run is
tests/integration/test_sshd_hardening.py)."""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = (REPO / "bootstrap" / "sshd-hardening.sh").read_text()
DROPIN = (REPO / "src" / "boxmunge" / "sshd" / "00-boxmunge.conf").read_text()

AUTH = {"PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
        "PermitRootLogin": "no"}
FORWARDING = {"X11Forwarding": "no", "AllowTcpForwarding": "no",
              "AllowStreamLocalForwarding": "no", "AllowAgentForwarding": "no",
              "PermitTunnel": "no", "GatewayPorts": "no"}
SESSION = {"PermitUserEnvironment": "no"}
DEPLOY_ONLY = {"DisableForwarding": "yes", "PermitUserRC": "no"}
ACCEPTENV = "AcceptEnv LANG LC_* COLORTERM NO_COLOR"


def _array(name: str) -> dict[str, str]:
    body = SCRIPT.split(f"{name}=(\n", 1)[1].split("\n)", 1)[0]
    return dict(re.findall(r'"(\S+) (\S+)"', body))


def test_the_drop_in_sorts_before_cloud_inits() -> None:
    assert 'DROPIN="/etc/ssh/sshd_config.d/00-boxmunge.conf"' in SCRIPT
    assert "00-boxmunge.conf" < "50-cloud-init.conf"


def _settings(lines: list[str]) -> dict[str, str]:
    return dict(line.split() for line in lines if line and not line.startswith("#"))


def test_the_drop_in_says_what_the_effective_settings_are_checked_against() -> None:
    assert _array("AUTH") == AUTH
    assert _array("FORWARDING") == FORWARDING
    assert _array("SESSION") == SESSION
    assert _array("DEPLOY_ONLY") == DEPLOY_ONLY
    globals_, match = DROPIN.split("\nMatch User deploy\n")
    assert _settings(globals_.splitlines()) == {**AUTH, **FORWARDING, **SESSION}
    lines = match.splitlines()
    assert all(line.startswith("    ") for line in lines)
    assert lines[0].strip() == ACCEPTENV
    assert _settings([line.strip() for line in lines[1:]]) == {**FORWARDING, **DEPLOY_ONLY}
    accepted = sorted(f"acceptenv {name}" for name in ACCEPTENV.split()[1:])
    assert f'DEPLOY_ACCEPTENV="{chr(10).join(accepted)}"' in SCRIPT
    assert "Match" not in match


def test_the_effective_settings_are_checked_for_both_accounts() -> None:
    assert ('missing_for deploy "${AUTH[@]}" "${FORWARDING[@]}" "${SESSION[@]}" '
            '"${DEPLOY_ONLY[@]}"') in SCRIPT
    assert 'missing_for supervisor "${AUTH[@]}"' in SCRIPT
    assert '/usr/sbin/sshd -T -C "user=${user}' in SCRIPT
    assert SCRIPT.index("/usr/sbin/sshd -t") < SCRIPT.index("systemctl try-reload-or-restart ssh")


def test_sshd_sh_leaves_these_keywords_to_the_drop_in() -> None:
    text = (REPO / "bootstrap" / "sshd.sh").read_text()
    for key in [*AUTH, *FORWARDING, "ChallengeResponseAuthentication"]:
        assert f"_set_sshd {key}" not in text


def test_a_fresh_bootstrap_applies_it_before_sshd_restarts() -> None:
    text = (REPO / "bootstrap" / "sshd.sh").read_text()
    call = 'bash "$(dirname "${BASH_SOURCE[0]}")/sshd-hardening.sh"'
    assert call in text
    assert text.index(call) < text.index("systemctl restart sshd")


def test_every_install_and_upgrade_applies_it_before_recording_the_installer() -> None:
    text = (REPO / "install.sh").read_text()
    call = 'bash "${SCRIPT_DIR}/bootstrap/sshd-hardening.sh"'
    assert call in text
    # A failed run leaves the old fingerprint, so the next upgrade re-runs install.sh.
    assert text.index(call) < text.index('INSTALLER_HASH_FILE="${BOXMUNGE_ROOT}/state/installer.sha256"')
    assert text.index(call) > text.index("init-host.sh")
