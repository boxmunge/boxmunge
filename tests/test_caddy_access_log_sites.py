# SPDX-License-Identifier: Apache-2.0
"""bootstrap/caddy-access-log.sh sites: which files the /var/log/caddy check reads.

#105: the check grepped all of caddy/sites recursively, so an operator's TLS
key in caddy/sites/tls/ that deploy cannot read made grep exit 2, install.sh
fail and the upgrade blocklist itself. It now reads what Caddy imports
(caddy/sites/*.conf), the pending journal entries (*.json) and the project
overrides: the rewrite's own scope. The end-to-end run as a real deploy user
is tests/integration/test_crowdsec_caddy_trixie.py.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "bootstrap" / "caddy-access-log.sh"

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")


@pytest.fixture
def box(tmp_path):
    root = tmp_path / "bm"
    (root / "caddy" / "sites").mkdir(parents=True)
    (root / "caddy" / ".site-journal").mkdir()
    (root / "projects" / "app").mkdir(parents=True)
    # runuser stand-in: run the command as this (non-root) user.
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    runuser = fakebin / "runuser"
    runuser.write_text('#!/usr/bin/env bash\n[[ "$1 $3" == "-u --" ]] || exit 64\nshift 3\nexec "$@"\n')
    runuser.chmod(0o755)
    return root, fakebin


def _sites(box) -> subprocess.CompletedProcess:
    root, fakebin = box
    env = {**os.environ, "BOXMUNGE_ROOT": str(root), "PATH": f"{fakebin}:{os.environ['PATH']}"}
    return subprocess.run(["bash", str(SCRIPT), "sites"], env=env, capture_output=True,
                          text=True, timeout=60, stdin=subprocess.DEVNULL)


def _unreadable(path: Path, text: str = "key material") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0)
    return path


def test_an_unreadable_file_beside_the_configs_is_not_read(box):
    root, _ = box
    sites = root / "caddy" / "sites"
    (sites / "app.conf").write_text("app.example.com {\n    tls /etc/caddy/sites/tls/origin.pem\n}\n")
    _unreadable(sites / "tls" / "origin.key")
    _unreadable(sites / "notes.txt")
    result = _sites(box)
    assert result.returncode == 0, result.stderr


def test_an_unreadable_subdirectory_is_not_entered(box):
    root, _ = box
    tls = root / "caddy" / "sites" / "tls"
    tls.mkdir()
    tls.chmod(0)
    try:
        result = _sites(box)
    finally:
        tls.chmod(0o755)
    assert result.returncode == 0, result.stderr


def test_a_linked_config_is_not_followed(box, tmp_path):
    root, _ = box
    (root / "caddy" / "sites" / "planted.conf").symlink_to(_unreadable(tmp_path / "victim"))
    result = _sites(box)
    assert result.returncode == 0, result.stderr


def test_nothing_to_check_passes(box):
    assert _sites(box).returncode == 0


@pytest.mark.parametrize("where", [
    "caddy/sites/app.conf", "caddy/.site-journal/app.conf.json", "projects/app/caddy.override.conf",
])
def test_a_config_still_naming_the_log_file_is_refused(box, where):
    root, _ = box
    text = "    log {\n        output file /var/log/caddy/other.log\n    }\n"
    if where.endswith(".json"):
        text = json.dumps({"path": "x", "previous": text, "written": text})
    (root / where).write_text(text)
    result = _sites(box)
    assert result.returncode == 1
    assert str(root / where) in result.stderr
    assert "Replace each log block" in result.stderr


def test_an_unreadable_config_is_still_an_error_naming_the_way_back(box):
    """Caddy imports it, so the check cannot pass it unread."""
    root, _ = box
    _unreadable(root / "caddy" / "sites" / "app.conf")
    result = _sites(box)
    assert result.returncode == 1
    assert "could not check" in result.stderr
    assert "boxmunge-upgrade clear-blocklist" in result.stderr
