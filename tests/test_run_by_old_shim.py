# SPDX-License-Identifier: Apache-2.0
"""bootstrap/run-by-old-shim.sh: install.sh recognises a shim from 0.7.0 to
0.10.0, which runs it mid-upgrade without --upgrade-shim.

Those shims hold the legacy lock on descriptor 9 (`exec 9>"$LOCK_FILE";
flock -n 9`) and install.sh inherits it. Each case runs the real script with
descriptor 9 set up the way a caller would leave it. The ones that matter
most are runs by hand: they must never be taken for a shim's, even while an
upgrade or health check holds the lock.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "bootstrap" / "run-by-old-shim.sh"

# Runs SCRIPT with descriptor 9 as described by argv: `<lock|other|none>
# <held-by-9|held-elsewhere|free>`. The lock is held with flock(2), as the
# shims hold it.
_CALLER = r"""
import fcntl, os, subprocess, sys
script, lock, other, fd9, hold = sys.argv[1:]
held_elsewhere = None
if hold == "held-elsewhere":
    held_elsewhere = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(held_elsewhere, fcntl.LOCK_EX | fcntl.LOCK_NB)
pass_fds = ()
if fd9 != "none":
    fd = os.open(lock if fd9 == "lock" else other, os.O_RDWR | os.O_CREAT, 0o600)
    if hold == "held-by-9":
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.dup2(fd, 9)
    pass_fds = (9,)
result = subprocess.run(["bash", script], pass_fds=pass_fds, capture_output=True, text=True,
                        env={**os.environ})
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
sys.exit(result.returncode)
"""


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "upgrade-state").mkdir()
    (tmp_path / "upgrade-state" / "upgrade.lock").touch()
    (tmp_path / "other").touch()
    return tmp_path


def _detect(root: Path, fd9: str, hold: str, lock: Path | None = None) -> subprocess.CompletedProcess:
    lock = lock or root / "upgrade-state" / "upgrade.lock"
    return subprocess.run(
        [sys.executable, "-c", _CALLER, str(SCRIPT), str(lock), str(root / "other"), fd9, hold],
        env={**os.environ, "BOXMUNGE_ROOT": str(root)}, capture_output=True, text=True, check=False,
    )


def test_a_shim_holding_the_legacy_lock_on_descriptor_9_is_recognised(root: Path) -> None:
    result = _detect(root, "lock", "held-by-9")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "1\n"


@pytest.mark.parametrize(("fd9", "hold"), [
    ("none", "free"),            # a run by hand: sudo closes inherited descriptors
    ("none", "held-elsewhere"),  # by hand, while an upgrade or health check holds the lock
    ("other", "held-elsewhere"),  # descriptor 9 open on something else
    ("lock", "free"),            # open on the lock, which nobody holds
])
def test_anything_else_is_a_run_by_hand(root: Path, fd9: str, hold: str) -> None:
    result = _detect(root, fd9, hold)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "0\n"


def test_a_link_at_the_lock_path_is_not_the_lock(root: Path) -> None:
    """upgrade-state/ is deploy-writable: a link planted there to a file this
    process holds open must not make a run by hand look like a shim's."""
    lock = root / "upgrade-state" / "upgrade.lock"
    lock.unlink()
    lock.symlink_to(root / "other")
    result = _detect(root, "other", "held-by-9", lock=root / "other")
    assert result.stdout == "0\n", result.stderr


def test_install_sh_takes_the_shim_path_when_it_is_recognised() -> None:
    """Asked when there is no --upgrade-shim, after the pre-flight guards
    and before the first step that changes the system."""
    install = (REPO / "install.sh").read_text()
    asked = install.index(
        '\n[[ "${FROM_UPGRADE_SHIM}" -eq 1 ]] || FROM_UPGRADE_SHIM="$(BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" '
        'bash "${SCRIPT_DIR}/bootstrap/run-by-old-shim.sh")"\n')
    assert install.index('if [[ "${1:-}" == "--upgrade-shim" ]]; then\n    FROM_UPGRADE_SHIM=1') < asked
    assert install.index("is the unbuilt source shim") < asked
    assert asked < install.index("\n# Docker Compose version.")
