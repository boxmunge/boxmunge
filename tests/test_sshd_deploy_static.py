"""deploy's sshd Match block closes every forwarding channel, and both a fresh
bootstrap and every install/upgrade apply it (the trixie run is
tests/integration/test_sshd_deploy_forwarding.py)."""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = (REPO / "bootstrap" / "sshd-deploy.sh").read_text()

CLOSED = {
    "DisableForwarding": "yes",
    "AllowTcpForwarding": "no",
    "AllowStreamLocalForwarding": "no",
    "AllowAgentForwarding": "no",
    "X11Forwarding": "no",
    "PermitTunnel": "no",
    "PermitUserRC": "no",
}


def _rendered_block() -> list[str]:
    body = SCRIPT.split("render() {\n", 1)[1].split("\n}\n", 1)[0]
    return re.findall(r'^\s*echo "(.*)"$', body, flags=re.MULTILINE)


def test_the_match_block_closes_every_channel_for_deploy() -> None:
    lines = [line for line in _rendered_block() if not line.startswith("#")]
    assert lines[0] == "Match User ${DEPLOY_USER}"
    directives = dict(line.split() for line in lines[1:])
    assert directives == CLOSED
    assert all(line.startswith("    ") for line in lines[1:])


def test_every_directive_is_checked_against_sshds_effective_settings() -> None:
    expected = SCRIPT.split("EXPECTED=(\n", 1)[1].split("\n)", 1)[0]
    checked = re.findall(r'"(\S+) (\S+)"', expected)
    assert dict(checked) == {key.lower(): value for key, value in CLOSED.items()}
    assert '/usr/sbin/sshd -T -C "user=${DEPLOY_USER}' in SCRIPT
    assert SCRIPT.index("/usr/sbin/sshd -t") < SCRIPT.index("systemctl try-reload-or-restart ssh")


def test_a_fresh_bootstrap_applies_it_before_sshd_restarts() -> None:
    text = (REPO / "bootstrap" / "sshd.sh").read_text()
    call = 'bash "$(dirname "${BASH_SOURCE[0]}")/sshd-deploy.sh"'
    assert call in text
    assert text.index(call) < text.index("systemctl restart sshd")


def test_every_install_and_upgrade_applies_it_before_recording_the_installer() -> None:
    text = (REPO / "install.sh").read_text()
    call = 'DEPLOY_USER=deploy bash "${SCRIPT_DIR}/bootstrap/sshd-deploy.sh"'
    assert call in text
    # A failed run leaves the old fingerprint, so the next upgrade re-runs install.sh.
    assert text.index(call) < text.index('INSTALLER_HASH_FILE="${BOXMUNGE_ROOT}/state/installer.sha256"')
    assert text.index(call) > text.index("init-host.sh")
