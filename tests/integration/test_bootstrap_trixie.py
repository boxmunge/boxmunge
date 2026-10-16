"""Run the bootstrap hardening scripts on a real Debian 13 (trixie) userland.

Each test starts a throwaway `debian:trixie` container, mounts bootstrap/
read-only, runs one script the way init-host.sh does, and checks the host
state it leaves behind. Needs Docker and network access to the Debian mirror.
"""
from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

import pytest

from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

REPO = Path(__file__).resolve().parents[2]
IMAGE = "debian:trixie"

# Minimal cloud images often turn Recommends off; the scripts must not rely on them.
_NO_RECOMMENDS = (
    "echo 'APT::Install-Recommends \"false\";' > /etc/apt/apt.conf.d/99norecommends\n"
)
_PRELUDE = (
    "set -u\n"
    "export DEBIAN_FRONTEND=noninteractive\n"
    + _NO_RECOMMENDS
    + "apt-get update -qq >/dev/null\n"
    # init-host.sh installs these before any hardening script runs.
    "apt-get install -y -qq ca-certificates curl >/dev/null\n"
)


def _run_on_trixie(script: str, timeout: int = 900) -> subprocess.CompletedProcess:
    name = f"bmtest-bootstrap-{uuid.uuid4().hex[:10]}"
    return subprocess.run(
        ["docker", "run", "--rm", "--name", name,
         "-v", f"{REPO / 'bootstrap'}:/bootstrap:ro",
         "-v", f"{REPO / 'install.sh'}:/install.sh:ro",
         IMAGE, "bash", "-c", _PRELUDE + script],
        capture_output=True, text=True, timeout=timeout, check=False,
    )


def test_aide_sh_installs_its_config_on_trixie() -> None:
    """aide.sh must not depend on aide's Recommends for /etc/aide (issue #1)."""
    result = _run_on_trixie(
        "bash /bootstrap/aide.sh > /tmp/aide.log 2>&1 || { tail -20 /tmp/aide.log; exit 1; }\n"
        "cat /etc/aide/aide.conf.d/90_boxmunge.conf\n"
        "test -x /etc/cron.daily/boxmunge-aide-check\n"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "/opt/boxmunge/config Full" in result.stdout


# No systemd in a container: a stub keeps the scripts' service steps from aborting.
_STUB_SYSTEMCTL = (
    "printf '#!/bin/sh\\nexit 0\\n' > /usr/local/bin/systemctl\n"
    "chmod +x /usr/local/bin/systemctl\n"
)


def test_crowdsec_sh_leaves_apt_working_on_trixie() -> None:
    """crowdsec.sh must not leave an apt source with no trixie release (issue #2)."""
    result = _run_on_trixie(
        _STUB_SYSTEMCTL
        + "bash /bootstrap/crowdsec.sh > /tmp/cs.log 2>&1 || { tail -20 /tmp/cs.log; exit 1; }\n"
        "command -v cscli\n"
        "ls /etc/apt/sources.list.d/\n"
        "apt-get update -qq 2>&1 || { echo APT_UPDATE_FAILED; exit 1; }\n"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "/usr/bin/cscli" in result.stdout
    assert "crowdsec_crowdsec.list" not in result.stdout


def test_install_sh_removes_the_dead_crowdsec_repo_on_trixie() -> None:
    """Hosts bootstrapped by earlier releases carry the dead packagecloud source;
    install.sh (run on every upgrade) removes it so apt-get update works again."""
    result = _run_on_trixie(
        "echo 'deb https://packagecloud.io/crowdsec/crowdsec/debian/ trixie main'"
        " > /etc/apt/sources.list.d/crowdsec_crowdsec.list\n"
        "apt-get update -qq >/dev/null 2>&1 && { echo SETUP_DID_NOT_BREAK_APT; exit 1; }\n"
        "eval \"$(sed -n '/^remove_dead_crowdsec_repo() {/,/^}/p' /install.sh)\"\n"
        "remove_dead_crowdsec_repo\n"
        "test ! -e /etc/apt/sources.list.d/crowdsec_crowdsec.list\n"
        "apt-get update -qq 2>&1 || { echo APT_UPDATE_FAILED; exit 1; }\n"
    )
    assert result.returncode == 0, result.stdout + result.stderr
