"""boxmunge's sshd drop-in on a real Debian 13 sshd (OpenSSH 10), on a cloud
image whose 50-cloud-init.conf says `PasswordAuthentication yes`.

sshd_hardening_probe.sh builds the box the way init-host.sh does and tries each
channel that would bypass deploy's restricted shell. deploy is in the docker
group, so a forwarded Docker socket is root. Without
bootstrap/sshd-hardening.sh such a box takes passwords and gives deploy
every channel; with it, only key logins and deploy's session remain, while
commands, the interactive shell and scp uploads still work.
"""
from __future__ import annotations

import subprocess
import uuid

import pytest

from tests.integration.conftest import skip_no_docker
from tests.integration.test_bootstrap_trixie import _NO_RECOMMENDS, IMAGE, REPO

pytestmark = [pytest.mark.integration, skip_no_docker]

CHANNELS = ("docker-sock-L", "tcp-L", "tcp-R", "streamlocal-R", "stdio-W", "agent")
LOGINS = ("passwordauthentication no", "kbdinteractiveauthentication no", "permitrootlogin no")
CLOSED = ("disableforwarding yes", "allowtcpforwarding no", "allowstreamlocalforwarding no",
          "allowagentforwarding no", "x11forwarding no", "permittunnel no",
          "gatewayports no", "permituserrc no")


def _docker_run(mounts: dict[str, str], script: str) -> subprocess.CompletedProcess:
    volumes = [arg for host, guest in mounts.items() for arg in ("-v", f"{host}:{guest}:ro")]
    return subprocess.run(
        ["docker", "run", "--rm", "--name", f"bmtest-sshd-hardening-{uuid.uuid4().hex[:10]}",
         *volumes, IMAGE, "bash", "-c", _NO_RECOMMENDS + script],
        capture_output=True, text=True, timeout=900, check=False,
    )


@pytest.fixture(scope="module")
def probe() -> dict[str, str]:
    result = _docker_run(
        {str(REPO / "bootstrap"): "/bootstrap", str(REPO / "src"): "/src",
         str(REPO / "install.sh"): "/install.sh",
         str(REPO / "tests/integration/sshd_hardening_probe.sh"): "/probe.sh"},
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
            phase, user, settings = rest.split(" ", 2)
            lines[f"SETTINGS {phase} {user}"] = settings
        elif tag == "SERVER":
            phase, _, output = rest.partition(" ")
            lines[f"SERVER {phase}"] = output
        elif tag in ("COMMAND", "TTY", "REFUSED", "INBOX"):
            lines[tag] = rest
    return lines


def _verdicts(probe: dict[str, str], phase: str) -> dict[str, str]:
    return {channel: probe[f"{phase} deploy {channel}"] for channel in CHANNELS}


def _settings(probe: dict[str, str], phase: str, user: str) -> list[str]:
    return probe[f"SETTINGS {phase} {user}"].split(",")


def test_without_the_drop_in_cloud_init_turns_passwords_on_and_deploy_can_forward(
        probe: dict[str, str]) -> None:
    assert _verdicts(probe, "fleet-before") == dict.fromkeys(CHANNELS, "allowed")
    for user in ("deploy", "supervisor"):
        assert "passwordauthentication yes" in _settings(probe, "fleet-before", user)


@pytest.mark.parametrize("phase", ["fleet-after", "relaxed-after"])
def test_with_the_drop_in_deploy_gets_key_logins_and_the_session_only(
        probe: dict[str, str], phase: str) -> None:
    assert _verdicts(probe, phase) == dict.fromkeys(CHANNELS, "refused")
    deploy = _settings(probe, phase, "deploy")
    for setting in LOGINS + CLOSED + ("permittty yes", "permituserenvironment no"):
        assert setting in deploy


def test_the_drop_in_beats_cloud_init_for_supervisor_too(probe: dict[str, str]) -> None:
    supervisor = _settings(probe, "fleet-after", "supervisor")
    for setting in LOGINS + ("allowtcpforwarding no", "allowagentforwarding no",
                             "allowstreamlocalforwarding no", "x11forwarding no"):
        assert setting in supervisor
    assert probe["fleet-after supervisor tcp-L"] == "refused"


def test_deploys_match_block_ends_with_its_file(probe: dict[str, str]) -> None:
    """sshd reads the main file after the drop-in: its settings stay global."""
    for user in ("deploy", "supervisor"):
        settings = _settings(probe, "fleet-after", user)
        assert "port 922" in settings and "maxauthtries 3" in settings
    supervisor = _settings(probe, "fleet-after", "supervisor")
    assert "disableforwarding no" in supervisor and "permituserrc yes" in supervisor
    deploy = [s for s in _settings(probe, "fleet-after", "deploy") if s.startswith("acceptenv")]
    assert sorted(deploy) == ["acceptenv COLORTERM", "acceptenv LANG", "acceptenv LC_*",
                              "acceptenv NO_COLOR"]


def test_an_operator_may_open_forwarding_for_supervisor_alone(probe: dict[str, str]) -> None:
    assert probe["fleet-before supervisor tcp-L"] == "allowed"
    assert probe["relaxed-after supervisor tcp-L"] == "allowed"


def test_a_client_bash_env_runs_code_only_before_the_fix(probe: dict[str, str]) -> None:
    assert probe["env-before deploy bash-env"] == "allowed"
    # sshd pins deploy's AcceptEnv: the variable never arrives.
    assert probe["env-after-sshd deploy bash-env"] == "refused"
    assert "BASH_ENV=unset" in probe["SERVER env-after-sshd"]
    # Widened again by a later Match block: sh and the shell drop it.
    assert probe["env-after-wrapper deploy bash-env"] == "refused"
    assert probe["SERVER env-after-wrapper"] == "boxmunge-server ran: status BASH_ENV=unset"


def test_deploy_commands_tty_and_scp_uploads_still_work(probe: dict[str, str]) -> None:
    assert probe["COMMAND"] == "boxmunge-server ran: status --json BASH_ENV=unset"
    assert probe["REFUSED"].startswith("ERROR: Unknown command 'cat'")
    assert int(probe["TTY"]) >= 1
    assert probe["INBOX"].startswith("demo-") and probe["INBOX"].endswith(".tar.gz")


_STUB_LOGGING_SYSTEMCTL = (
    "printf '#!/bin/sh\\necho \"$*\" >> /tmp/systemctl.log\\n' > /usr/local/bin/systemctl\n"
    "chmod +x /usr/local/bin/systemctl\n"
)
_RUN = "bash /bootstrap/sshd-hardening.sh"
_DROPIN = "/etc/ssh/sshd_config.d/00-boxmunge.conf"


def test_sshd_hardening_sh_is_idempotent_and_fails_loudly_on_trixie() -> None:
    result = _docker_run(
        {str(REPO / "bootstrap"): "/bootstrap", str(REPO / "src"): "/src"},
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get update -qq >/dev/null && apt-get install -y -qq openssh-server >/dev/null\n"
        + _STUB_LOGGING_SYSTEMCTL +
        "ssh-keygen -A >/dev/null; useradd deploy; useradd supervisor\n"
        "echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/50-cloud-init.conf\n"
        f"{_RUN} >/dev/null && echo first=ok\n"
        f"{_RUN} && echo second=ok\n"
        "echo reloads=$(grep -c . /tmp/systemctl.log)\n"
        # A drop-in read before ours wins: refused, the previous drop-in put back.
        f"echo '# stale' >> {_DROPIN}\n"
        "printf 'PasswordAuthentication yes\\nMatch User deploy\\n    AllowAgentForwarding yes\\n'"
        " > /etc/ssh/sshd_config.d/00-aaa.conf\n"
        f"{_RUN} 2>/tmp/err; echo shadowed=$?; cat /tmp/err\n"
        f"tail -1 {_DROPIN}\n"
        "rm /etc/ssh/sshd_config.d/00-aaa.conf\n"
        # A later Match block widening deploy's AcceptEnv, or a user environment
        # file allowed first: both refused.
        "printf 'Match User deploy\\n    AcceptEnv *\\n' > /etc/ssh/sshd_config.d/30-widen.conf\n"
        f"{_RUN} 2>/tmp/err; echo widened=$?; cat /tmp/err\n"
        "rm /etc/ssh/sshd_config.d/30-widen.conf\n"
        "echo 'PermitUserEnvironment yes' > /etc/ssh/sshd_config.d/00-aaa.conf\n"
        f"{_RUN} 2>/tmp/err; echo userenv=$?; cat /tmp/err\n"
        "rm /etc/ssh/sshd_config.d/00-aaa.conf\n"
        # keyboard-interactive 2FA cannot be satisfied once it is off: sshd -t
        # refuses, the drop-in is put back, and nothing is reloaded.
        f"cp {_DROPIN} /tmp/before.conf; echo '# 2fa' >> {_DROPIN}\n"
        "cp /etc/ssh/sshd_config /tmp/main.conf\n"
        "echo 'AuthenticationMethods publickey,keyboard-interactive' >> /etc/ssh/sshd_config\n"
        f"{_RUN} 2>/tmp/err; echo twofactor=$?; cat /tmp/err; tail -1 {_DROPIN}\n"
        "echo reloads-now=$(grep -c . /tmp/systemctl.log)\n"
        f"cp /tmp/main.conf /etc/ssh/sshd_config; cp /tmp/before.conf {_DROPIN}\n"
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
    assert "hardening already applied" in out
    assert "reloads=1" in out
    assert "shadowed=1" in out
    for missing in ("deploy: PasswordAuthentication no", "supervisor: PasswordAuthentication no",
                    "deploy: AllowAgentForwarding no"):
        assert missing in out
    assert "# stale" in out  # the previous drop-in was put back as it was
    assert "widened=1" in out and "AcceptEnv LANG LC_* COLORTERM NO_COLOR and nothing more" in out
    assert "acceptenv *" in out
    assert "userenv=1" in out and "deploy: PermitUserEnvironment no" in out
    assert "twofactor=1" in out and "keyboard-interactive" in out
    assert "# 2fa" in out and "reloads-now=1" in out
    assert "noinclude=1" in out and "Include /etc/ssh/sshd_config.d/*.conf" in out
    assert "removed" in out
    assert "invalid=1" in out and "Bogus" in out
