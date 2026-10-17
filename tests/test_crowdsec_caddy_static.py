"""CrowdSec reads Caddy's access log through Docker, never from a file.

Static checks on what the bootstrap and install scripts write; the end-to-end
run on Debian 13's CrowdSec is tests/integration/test_crowdsec_caddy_trixie.py.
"""
from __future__ import annotations

import configparser
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from boxmunge.caddy import ACCESS_LOG_FIELD_LIMITS, _access_log_lines, generate_caddy_config
from boxmunge.docker import _CADDY_CONTAINER

REPO = Path(__file__).resolve().parents[1]
BOOTSTRAP = REPO / "bootstrap"
CROWDSEC_CADDY = (BOOTSTRAP / "crowdsec-acquis.sh").read_text()


def _heredoc(text: str, start: str, end: str) -> str:
    body = text.split(start, 1)[1]
    return body.split(f"\n{end}\n", 1)[0].lstrip("\n")


def _caddy_service() -> dict:
    return yaml.safe_load((REPO / "caddy" / "compose.yml").read_text())["services"]["caddy"]


def test_caddy_mounts_no_log_directory() -> None:
    for volume in _caddy_service()["volumes"]:
        assert "/var/log" not in volume and "logs" not in volume.split(":")[0]


def test_old_log_path_is_only_a_small_container_private_tmpfs() -> None:
    """Room for the old configs' own rotation (roll_size 50MiB, roll_keep 5,
    plus the file being written), so a rolled-back Caddy never fills it."""
    assert _caddy_service()["tmpfs"] == ["/var/log/caddy:size=320m,mode=0700"]


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
        "follow_stdout": True, "follow_stderr": False, "labels": {"type": "boxmunge-caddy"},
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
    crowdsec = text.index('bootstrap/crowdsec-acquis.sh"')
    assert sites < copy < up < retire < crowdsec


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


# Each site block's access log as caddy.py generated it before this release.
OLD_LOG = (
    "    log {\n"
    "        output file /var/log/caddy/access.log {\n"
    "            roll_size 50MiB\n"
    "            roll_keep 5\n"
    "        }\n"
    "        format json\n"
    "    }\n"
)
MANIFEST = {
    "project": "myapp", "hosts": ["myapp.example.com"],
    "services": {"web": {"type": "frontend", "port": 3000, "routes": [{"path": "/"}]}},
}


def _rewrite_program() -> str:
    script = (BOOTSTRAP / "caddy-access-log.sh").read_text()
    return script.split("REWRITE=\"$(cat <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]


def _new_log() -> str:
    return "\n".join(_access_log_lines()) + "\n"


def test_sites_rewrite_knows_the_current_log_block() -> None:
    namespace: dict = {}
    program = _rewrite_program()
    exec(program.split("\n\ndef rewrite", 1)[0], namespace)  # OLD and NEW only
    assert namespace["NEW"] == _new_log()
    assert namespace["OLD"] == OLD_LOG


def test_sites_rewrite_moves_sites_and_journal_and_skips_what_it_must_not_open(tmp_path) -> None:
    sites, journal = tmp_path / "sites", tmp_path / ".site-journal"
    sites.mkdir()
    journal.mkdir()
    new = generate_caddy_config(MANIFEST)
    old = new.replace(_new_log(), OLD_LOG)
    assert old != new
    (sites / "myapp.conf").write_text(old)
    (sites / "myapp.conf").chmod(0o644)
    victim = tmp_path / "victim"
    victim.write_text(OLD_LOG)
    (sites / "planted.conf").symlink_to(victim)
    os.mkfifo(sites / "fifo.conf")
    # What the first version's fixed temporary name left (a crash, or planted):
    # a rerun must not trip over it.
    (sites / "myapp.conf.boxmunge-rewrite").write_text("stale")
    (journal / "myapp.conf.json").write_text(
        json.dumps({"path": "x", "previous": old, "written": old}))
    for _ in range(2):  # idempotent
        subprocess.run([sys.executable, "-I", "-c", _rewrite_program(), str(sites), str(journal)],
                       check=True, timeout=30)
    assert (sites / "myapp.conf").read_text() == new
    assert stat.S_IMODE((sites / "myapp.conf").stat().st_mode) == 0o644
    assert json.loads((journal / "myapp.conf.json").read_text()) == {
        "path": "x", "previous": new, "written": new}
    assert victim.read_text() == OLD_LOG and (sites / "planted.conf").is_symlink()
    assert sorted(p.name for p in sites.iterdir()) == [
        "fifo.conf", "myapp.conf", "myapp.conf.boxmunge-rewrite", "planted.conf"]


def test_every_access_line_stays_far_below_crowdsecs_64k_line_limit() -> None:
    """CrowdSec 1.4.6's docker source drops a line over 64 KiB and loses the
    lines after it. Caddy JSON-escapes a byte into at most six (\\ufffd), so
    only fields cut to a fixed length may carry client or upstream text."""
    lines = _access_log_lines()
    for dropped in ("request>headers", "request>tls", "resp_headers"):
        assert f"                {dropped} delete" in lines
    for name, limit in ACCESS_LOG_FIELD_LIMITS.items():
        caps = [line for line in lines if line.lstrip().startswith(f"{name} regexp ")]
        assert len(caps) == 1
        # Fixed widths: a value no longer than the limit does not match at all.
        assert re.search(r'regexp "\^\((\.\{\d+\})+\)\.\+\$" "\$\{1\}"$', caps[0]), caps[0]
        counts = [int(n) for n in re.findall(r"\.\{(\d+)\}", caps[0])]
        assert sum(counts) == limit and all(n <= 1000 for n in counts)  # Go's repeat limit
    fixed = 2048  # keys, addresses, numbers, Caddy's own strings
    assert 6 * sum(ACCESS_LOG_FIELD_LIMITS.values()) + fixed < 32 * 1024


def test_boxmunge_parser_feeds_the_hub_http_scenarios() -> None:
    body = _heredoc(CROWDSEC_CADDY, "\"${PARSER}.tmp\" <<'YAML'", "YAML")
    doc = yaml.safe_load(body)
    assert doc["filter"] == "evt.Parsed.program == 'boxmunge-caddy'"
    statics = {(s.get("meta") or s.get("parsed") or s.get("target"), s.get("expression"))
               for s in doc["statics"]}
    assert ("http_user_agent", 'JsonExtract(evt.Line.Raw, "user_agent")') in statics
    assert ("source_ip", 'JsonExtract(evt.Line.Raw, "request.remote_ip")') in statics
    assert ("evt.Parsed.request", 'JsonExtract(evt.Line.Raw, "request.uri")') in statics
    keys = {s.get("meta") or s.get("parsed") for s in doc["statics"]}
    # http-bad-user-agent reads evt.Parsed, the other scenarios evt.Meta.
    assert {"log_type", "service", "http_status", "http_path", "verb", "http_verb",
            "target_fqdn", "http_user_agent"} <= keys
