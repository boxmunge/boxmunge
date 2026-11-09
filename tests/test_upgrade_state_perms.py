# SPDX-License-Identifier: Apache-2.0
"""bootstrap/upgrade-state-perms.sh: install.sh's repair of upgrade-state/.

#107: install.sh ran `chown -R root:deploy upgrade-state` and then made only
active-slot and blocklist.json group read/write, which left probation.json
root:deploy 0600, so every deploy during probation crashed reading it. Each
state file deploy reads now gets group deploy and 0660, and the repair never
follows a link deploy planted in its own writable directory.
"""
from __future__ import annotations

import grp
import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "bootstrap" / "upgrade-state-perms.sh"
INSTALL = (REPO / "install.sh").read_text()


def _run(root: Path) -> subprocess.CompletedProcess:
    # Off a box there is no deploy group: use one this user is in.
    env = {**os.environ, "BOXMUNGE_ROOT": str(root),
           "DEPLOY_GROUP": grp.getgrgid(os.getgid()).gr_name}
    return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True,
                          text=True, timeout=30)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


@pytest.fixture
def state(tmp_path):
    d = tmp_path / "upgrade-state"
    d.mkdir()
    return d


def test_state_files_become_group_read_write(state):
    for name in ("active-slot", "blocklist.json", "probation.json"):
        (state / name).write_text("x")
        (state / name).chmod(0o600)
    result = _run(state.parent)
    assert result.returncode == 0, result.stderr
    for name in ("active-slot", "blocklist.json", "probation.json"):
        assert _mode(state / name) == 0o660, name
        assert (state / name).stat().st_gid == os.getgid()


def test_missing_files_are_fine(state):
    result = _run(state.parent)
    assert result.returncode == 0, result.stderr
    assert list(state.iterdir()) == []


def test_other_files_are_left_alone(state):
    (state / "upgrade.lock").write_text("")
    (state / "upgrade.lock").chmod(0o600)
    assert _run(state.parent).returncode == 0
    assert _mode(state / "upgrade.lock") == 0o600


def test_a_planted_link_is_not_followed(state, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("secret")
    victim.chmod(0o600)
    (state / "probation.json").symlink_to(victim)
    os.mkfifo(state / "blocklist.json")
    result = _run(state.parent)
    assert result.returncode == 0, result.stderr
    assert _mode(victim) == 0o600
    assert "probation.json is not a plain regular file; left as is" in result.stderr
    assert "blocklist.json is not a plain regular file; left as is" in result.stderr


def test_a_planted_socket_is_left_alone(state, monkeypatch):
    """Opening a socket fails (ENXIO, or EOPNOTSUPP on some systems) instead
    of returning a descriptor: that must not stop the installer."""
    monkeypatch.chdir(state)  # a relative bind keeps under AF_UNIX's path limit
    with socket.socket(socket.AF_UNIX) as sock:
        sock.bind("probation.json")
        result = _run(state.parent)
    assert result.returncode == 0, result.stderr
    assert "probation.json is not a plain regular file; left as is" in result.stderr


def test_install_sh_no_longer_reowns_the_whole_directory():
    assert 'chown -R root:deploy "${BOXMUNGE_ROOT}/upgrade-state"' not in INSTALL
    assert 'bootstrap/upgrade-state-perms.sh"' in INSTALL
