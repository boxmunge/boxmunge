"""deploy's SSH key reaches the restricted shell and nothing else, on a real
Debian 13 sshd (OpenSSH 10).

sshd_deploy_probe.sh builds the box the way init-host.sh does and tries each
channel that would bypass the shell. deploy is in the docker group, so a
forwarded Docker socket is root. Without bootstrap/sshd-deploy.sh, the
released config already leaves agent forwarding open, and turning TCP
forwarding on globally (for supervisor, say) hands deploy the Docker socket;
with it every channel is refused while sessions, commands and scp uploads
still work.
"""
from __future__ import annotations

import subprocess
import uuid

import pytest

from tests.integration.conftest import skip_no_docker
from tests.integration.test_bootstrap_trixie import _NO_RECOMMENDS, IMAGE, REPO

pytestmark = [pytest.mark.integration, skip_no_docker]

CHANNELS = ("docker-sock-L", "tcp-L", "tcp-R", "streamlocal-R", "stdio-W", "agent")
CLOSED = ("disableforwarding yes", "allowtcpforwarding no", "allowstreamlocalforwarding no",
          "allowagentforwarding no", "x11forwarding no", "permittunnel no", "permituserrc no")


def _docker_run(mounts: dict[str, str], script: str) -> subprocess.CompletedProcess:
    volumes = [arg for host, guest in mounts.items() for arg in ("-v", f"{host}:{guest}:ro")]
    return subprocess.run(
        ["docker", "run", "--rm", "--name", f"bmtest-sshd-deploy-{uuid.uuid4().hex[:10]}",
         *volumes, IMAGE, "bash", "-c", _NO_RECOMMENDS + script],
        capture_output=True, text=True, timeout=900, check=False,
    )


@pytest.fixture(scope="module")
def probe() -> dict[str, str]:
    result = _docker_run(
        {str(REPO / "bootstrap"): "/bootstrap", str(REPO / "src"): "/src",
         str(REPO / "tests/integration/sshd_deploy_probe.sh"): "/probe.sh"},
        "bash /probe.sh",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    lines: dict[str, str] = {}
    for line in result.stdout.splitlines():
        tag, _, rest = line.partition(" ")
        if tag == "RESULT":
            phase, user, channel, verdict = rest.split()
            lines[f"{phase} {user} {channel}"] = verdict
        elif tag == "SETTINGS":
            phase, _, settings = rest.partition(" ")
            lines[f"SETTINGS {phase}"] = settings
        elif tag in ("COMMAND", "TTY", "REFUSED", "INBOX"):
            lines[tag] = rest
    return lines


def _verdicts(probe: dict[str, str], phase: str) -> dict[str, str]:
    return {channel: probe[f"{phase} deploy {channel}"] for channel in CHANNELS}


def test_released_config_leaves_agent_forwarding_open_to_deploy(probe: dict[str, str]) -> None:
    verdicts = _verdicts(probe, "shipped-before")
    assert verdicts.pop("agent") == "allowed"
    assert set(verdicts.values()) == {"refused"}, verdicts
    assert "allowstreamlocalforwarding yes" in probe["SETTINGS shipped-before"]


def test_without_the_fix_global_tcp_forwarding_hands_deploy_the_docker_socket(
        probe: dict[str, str]) -> None:
    assert _verdicts(probe, "opened-before") == dict.fromkeys(CHANNELS, "allowed")


@pytest.mark.parametrize("phase", ["opened-after", "shipped-after"])
def test_with_the_fix_deploy_gets_no_channel_but_the_session(
        probe: dict[str, str], phase: str) -> None:
    assert _verdicts(probe, phase) == dict.fromkeys(CHANNELS, "refused")
    settings = probe[f"SETTINGS {phase}"].split(",")
    for setting in CLOSED:
        assert setting in settings
    assert "permittty yes" in settings


def test_the_fix_leaves_supervisor_forwarding_to_the_global_settings(
        probe: dict[str, str]) -> None:
    assert probe["opened-after supervisor tcp-L"] == "allowed"


def test_deploy_commands_tty_and_scp_uploads_still_work(probe: dict[str, str]) -> None:
    assert probe["COMMAND"] == "boxmunge-server ran: status --json"
    assert probe["REFUSED"].startswith("ERROR: Unknown command 'cat'")
    assert int(probe["TTY"]) >= 1
    assert probe["INBOX"].startswith("demo-") and probe["INBOX"].endswith(".tar.gz")


_STUB_LOGGING_SYSTEMCTL = (
    "printf '#!/bin/sh\\necho \"$*\" >> /tmp/systemctl.log\\n' > /usr/local/bin/systemctl\n"
    "chmod +x /usr/local/bin/systemctl\n"
)
_RUN = "DEPLOY_USER=deploy bash /bootstrap/sshd-deploy.sh"
_DROPIN = "/etc/ssh/sshd_config.d/00-boxmunge-deploy.conf"


def test_sshd_deploy_sh_is_idempotent_and_fails_loudly_on_trixie() -> None:
    result = _docker_run(
        {str(REPO / "bootstrap"): "/bootstrap"},
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get update -qq >/dev/null && apt-get install -y -qq openssh-server >/dev/null\n"
        + _STUB_LOGGING_SYSTEMCTL +
        "ssh-keygen -A >/dev/null; useradd deploy\n"
        f"{_RUN} >/dev/null && echo first=ok\n"
        f"{_RUN} && echo second=ok\n"
        "echo reloads=$(grep -c . /tmp/systemctl.log)\n"
        # An earlier drop-in that re-opens agent forwarding for deploy wins: refused, rolled back.
        f"cp {_DROPIN} /tmp/good.conf; echo '# stale' >> {_DROPIN}\n"
        "printf 'Match User deploy\\n    AllowAgentForwarding yes\\n'"
        " > /etc/ssh/sshd_config.d/00-aaa.conf\n"
        f"{_RUN} 2>/tmp/err; echo shadowed=$?; cat /tmp/err\n"
        f"tail -1 {_DROPIN}\n"
        "rm /etc/ssh/sshd_config.d/00-aaa.conf\n"
        # sshd that never reads the drop-in directory: refused, new file removed.
        f"rm {_DROPIN}; sed -i '/^Include/d' /etc/ssh/sshd_config\n"
        f"{_RUN} 2>/tmp/err; echo noinclude=$?; cat /tmp/err\n"
        f"test -e {_DROPIN} && echo left-behind || echo removed\n"
        # A main config sshd rejects: refused with sshd's own message.
        "echo 'Bogus yes' >> /etc/ssh/sshd_config\n"
        f"{_RUN} 2>/tmp/err; echo invalid=$?; cat /tmp/err\n",
    )
    out = result.stdout
    assert "first=ok" in out and "second=ok" in out, out + result.stderr
    assert "forwarding already closed for deploy" in out
    assert "reloads=1" in out
    assert "shadowed=1" in out and "allowagentforwarding no" in out
    assert "# stale" in out  # the previous drop-in was put back as it was
    assert "noinclude=1" in out and "Include /etc/ssh/sshd_config.d/*.conf" in out
    assert "removed" in out
    assert "invalid=1" in out and "Bogus" in out
