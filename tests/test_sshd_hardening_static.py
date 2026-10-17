"""boxmunge's sshd drop-in sorts first, closes logins and forwarding, and both
a fresh bootstrap and every install/upgrade apply it (the trixie run is
tests/integration/test_sshd_hardening.py)."""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = (REPO / "bootstrap" / "sshd-hardening.sh").read_text()

AUTH = {"PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
        "PermitRootLogin": "no"}
FORWARDING = {"X11Forwarding": "no", "AllowTcpForwarding": "no",
              "AllowStreamLocalForwarding": "no", "AllowAgentForwarding": "no",
              "PermitTunnel": "no", "GatewayPorts": "no"}
DEPLOY_ONLY = {"DisableForwarding": "yes", "PermitUserRC": "no"}


def _array(name: str) -> dict[str, str]:
    body = SCRIPT.split(f"{name}=(\n", 1)[1].split("\n)", 1)[0]
    return dict(re.findall(r'"(\S+) (\S+)"', body))


def test_the_drop_in_sorts_before_cloud_inits() -> None:
    assert 'DROPIN="/etc/ssh/sshd_config.d/00-boxmunge.conf"' in SCRIPT
    assert "00-boxmunge.conf" < "50-cloud-init.conf"


def test_globals_and_deploys_match_block_close_logins_and_forwarding() -> None:
    assert _array("AUTH") == AUTH
    assert _array("FORWARDING") == FORWARDING
    assert _array("DEPLOY_ONLY") == DEPLOY_ONLY
    render = SCRIPT.split("render() {\n", 1)[1].split("\n}\n", 1)[0]
    globals_, match = render.split('echo "Match User ${DEPLOY_USER}"')
    assert '"${AUTH[@]}" "${FORWARDING[@]}"' in globals_
    assert '"${FORWARDING[@]}" "${DEPLOY_ONLY[@]}"' in match


def test_the_effective_settings_are_checked_for_both_accounts() -> None:
    assert 'missing_for "${DEPLOY_USER}" "${AUTH[@]}" "${FORWARDING[@]}" "${DEPLOY_ONLY[@]}"' \
        in SCRIPT
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
    call = 'DEPLOY_USER=deploy bash "${SCRIPT_DIR}/bootstrap/sshd-hardening.sh"'
    assert call in text
    # A failed run leaves the old fingerprint, so the next upgrade re-runs install.sh.
    assert text.index(call) < text.index('INSTALLER_HASH_FILE="${BOXMUNGE_ROOT}/state/installer.sha256"')
    assert text.index(call) > text.index("init-host.sh")
