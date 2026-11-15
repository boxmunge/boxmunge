# SPDX-License-Identifier: Apache-2.0
"""bootstrap/jobs-dirs.sh makes state/jobs/, state/jobs/queue/ and the jobs
gate, deploy's, as the upgrade shim makes a missing jobs/ and gate. state/ is
deploy-writable, so a link or the wrong kind of file at a name fails the
install, naming it; nothing is followed. Run here as the test user, standing
in for deploy."""
from __future__ import annotations

import grp
import os
import pwd
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "bootstrap" / "jobs-dirs.sh"


def _run(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, check=False,
        env={"PATH": os.environ["PATH"], "BOXMUNGE_ROOT": str(root),
             "DEPLOY_USER": pwd.getpwuid(os.getuid()).pw_name,
             "DEPLOY_GROUP": grp.getgrgid(os.getgid()).gr_name})


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "state").mkdir()
    return tmp_path


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_makes_the_queue_and_the_gate_with_their_modes(root) -> None:
    result = _run(root)
    assert result.returncode == 0, result.stderr
    jobs = root / "state" / "jobs"
    assert (_mode(jobs), _mode(jobs / "queue"), _mode(jobs / "gate.lock")) == (0o750, 0o750, 0o660)
    assert stat.S_ISREG(os.lstat(jobs / "gate.lock").st_mode)
    for path in (jobs, jobs / "queue", jobs / "gate.lock"):
        st = os.lstat(path)
        assert (st.st_uid, st.st_gid) == (os.getuid(), os.getgid())


def test_is_idempotent_and_never_replaces_the_gate(root) -> None:
    assert _run(root).returncode == 0
    gate = root / "state" / "jobs" / "gate.lock"
    inode = os.lstat(gate).st_ino
    (root / "state" / "jobs" / "queue").chmod(0o755)   # as job_writer's mkdir left it
    result = _run(root)
    assert result.returncode == 0, result.stderr
    assert os.lstat(gate).st_ino == inode
    assert _mode(root / "state" / "jobs" / "queue") == 0o750


@pytest.mark.parametrize("name", ["jobs", "jobs/queue", "jobs/gate.lock"])
def test_a_link_at_a_name_fails_the_install_naming_it(root, tmp_path, name) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    planted = root / "state" / name
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.symlink_to(elsewhere)
    result = _run(root)
    assert result.returncode != 0
    assert f"{planted} is a symlink" in result.stderr
    assert list(elsewhere.iterdir()) == []


def test_a_gate_that_is_not_a_regular_file_fails_the_install(root) -> None:
    gate = root / "state" / "jobs" / "gate.lock"
    gate.mkdir(parents=True)
    result = _run(root)
    assert result.returncode != 0 and str(gate) in result.stderr


def test_install_sh_makes_them_before_the_units() -> None:
    text = (REPO / "install.sh").read_text()
    call = 'bash "${SCRIPT_DIR}/bootstrap/jobs-dirs.sh"'
    assert call in text
    assert text.index(call) < text.index('bootstrap/systemd-units.sh" "${SCRIPT_DIR}"')
