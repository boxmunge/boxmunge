"""CrowdSec reads Caddy's access log through Docker, never from a file.

Static checks on what the bootstrap and install scripts write; the end-to-end
run on Debian 13's CrowdSec is tests/integration/test_crowdsec_caddy_trixie.py.
"""
from __future__ import annotations

import configparser
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from boxmunge.caddy import generate_caddy_config
from boxmunge.docker import _CADDY_CONTAINER

REPO = Path(__file__).resolve().parents[1]
BOOTSTRAP = REPO / "bootstrap"
CROWDSEC_CADDY = (BOOTSTRAP / "crowdsec-caddy.sh").read_text()


def _heredoc(text: str, start: str, end: str) -> str:
    body = text.split(start, 1)[1]
    return body.split(f"\n{end}\n", 1)[0].lstrip("\n")


def _caddy_service() -> dict:
    return yaml.safe_load((REPO / "caddy" / "compose.yml").read_text())["services"]["caddy"]


def test_caddy_mounts_no_log_directory() -> None:
    for volume in _caddy_service()["volumes"]:
        assert "/var/log" not in volume and "logs" not in volume.split(":")[0]


def test_caddy_logs_to_a_driver_the_docker_api_reads_back_rotated() -> None:
    logging = _caddy_service()["logging"]
    assert logging["driver"] == "json-file"
    assert logging["options"] == {"max-size": "50m", "max-file": "5"}


def test_acquisition_reads_caddys_stdout_through_docker() -> None:
    body = _heredoc(CROWDSEC_CADDY, '"${ACQUIS}.tmp" <<YAML', "YAML")
    name = re.search(r"^CADDY_CONTAINER=(\S+)$", CROWDSEC_CADDY, re.M).group(1)
    doc = yaml.safe_load(body.replace("${CADDY_CONTAINER}", name))
    assert doc == {
        "source": "docker", "container_name": [_CADDY_CONTAINER],
        "follow_stdout": True, "follow_stderr": False, "labels": {"type": "caddy"},
    }
    assert _caddy_service()["container_name"] == _CADDY_CONTAINER


def test_limits_drop_in_bounds_crowdsec_and_restarts_it() -> None:
    body = _heredoc(CROWDSEC_CADDY, "\"${DROPIN}.tmp\" <<'UNIT'", "UNIT")
    unit = configparser.ConfigParser(strict=False, interpolation=None)
    unit.optionxform = str
    unit.read_string(body)
    service = unit["Service"]
    assert service["MemoryMax"] == "512M"
    assert service["TasksMax"] == "256"
    assert service["Restart"] == "on-failure"
    assert service["Environment"] == "GOMEMLIMIT=400MiB"


@pytest.mark.parametrize("script", ["crowdsec.sh", "init-host.sh"])
def test_no_bootstrap_script_points_crowdsec_at_a_file_under_caddy(script: str) -> None:
    text = (BOOTSTRAP / script).read_text()
    assert "source: file" not in text
    assert "/var/log/caddy" not in text
    assert '"${BOXMUNGE_ROOT}/caddy/logs"' not in text


def test_init_host_installs_the_bundled_caddy_compose() -> None:
    text = (BOOTSTRAP / "init-host.sh").read_text()
    assert '"$(dirname "$0")/../caddy/compose.yml"' in text
    assert "container_name: boxmunge-caddy" not in text


def test_install_moves_sites_before_recreating_caddy_then_switches_crowdsec() -> None:
    text = (REPO / "install.sh").read_text()
    sites = text.index('caddy-access-log.sh" sites')
    copy = text.index('cp "${SCRIPT_DIR}/caddy/compose.yml"')
    up = text.index('docker compose -f "${BOXMUNGE_ROOT}/caddy/compose.yml" up -d')
    retire = text.index('caddy-access-log.sh" retire')
    crowdsec = text.index('bootstrap/crowdsec-caddy.sh"')
    assert sites < copy < up < retire < crowdsec


@pytest.mark.skipif(shutil.which("perl") is None, reason="needs perl")
def test_sites_rewrite_turns_the_old_block_into_exactly_the_new_one() -> None:
    script = (BOOTSTRAP / "caddy-access-log.sh").read_text()
    old_block = re.search(r"^OLD_BLOCK='(.*)'$", script, re.M).group(1)
    new = generate_caddy_config({
        "project": "myapp", "hosts": ["myapp.example.com"],
        "services": {"web": {"type": "frontend", "port": 3000, "routes": [{"path": "/"}]}},
    })
    old = new.replace(
        "        output stdout\n",
        "        output file /var/log/caddy/access.log {\n"
        "            roll_size 50MiB\n            roll_keep 5\n        }\n")
    assert old != new
    rewritten = subprocess.run(
        ["perl", "-0777", "-pe", f"s/{old_block}/output stdout\\n/g"],
        input=old, capture_output=True, text=True, check=True).stdout
    assert rewritten == new


@pytest.mark.skipif(shutil.which("perl") is None, reason="needs perl")
def test_legacy_removal_drops_exactly_the_block_crowdsec_sh_appended() -> None:
    expr = re.search(r"-pe \\\n\s+'(.*)' \\\n", CROWDSEC_CADDY).group(1)
    ours = ("\n---\nsource: file\nfilenames:\n  - /opt/boxmunge/caddy/logs/access.log\n"
            "labels:\n  type: caddy\n")
    debian = "source: journalctl\njournalctl_filter:\n - \"_SYSTEMD_UNIT=ssh.service\"\n"
    out = subprocess.run(
        ["perl", "-0777", "-pe", expr], input=debian + ours,
        env={"LEGACY_LOG": "/opt/boxmunge/caddy/logs/access.log", "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, check=True).stdout
    assert out == debian
