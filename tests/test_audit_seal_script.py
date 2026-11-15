# SPDX-License-Identifier: Apache-2.0
"""bootstrap/audit-seal.sh seals the audit log with this release's code:
env-active's when run by hand, the standby slot's under the upgrade shim
(env-active is still the previous release, which has no _audit-seal)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "bootstrap" / "audit-seal.sh"


def _box(tmp_path: Path, live: str) -> Path:
    root = tmp_path / "bm"
    for slot in "ab":
        bin_dir = root / f"env-{slot}" / "bin"
        bin_dir.mkdir(parents=True)
        stub = bin_dir / "boxmunge-server"
        stub.write_text(f'#!/usr/bin/env bash\necho "env-{slot} $*" >> "{tmp_path}/ran"\n')
        stub.chmod(0o755)
    (root / "env-active").symlink_to(root / f"env-{live}")
    return root


def _run(root: Path, shim: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, check=False,
                          env={"PATH": "/usr/bin:/bin", "BOXMUNGE_ROOT": str(root),
                               "FROM_UPGRADE_SHIM": shim})


@pytest.mark.parametrize(("live", "shim", "used"), [
    ("a", "0", "env-a"), ("b", "0", "env-b"), ("a", "1", "env-b"), ("b", "1", "env-a"),
])
def test_seals_with_this_releases_slot(tmp_path, live, shim, used) -> None:
    result = _run(_box(tmp_path, live), shim)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "ran").read_text() == f"{used} _audit-seal\n"


def test_an_unknown_live_slot_under_the_shim_fails_naming_it(tmp_path) -> None:
    root = _box(tmp_path, "a")
    (root / "env-active").unlink()
    (root / "env-active").symlink_to(tmp_path / "elsewhere")
    result = _run(root, "1")
    assert result.returncode == 1
    assert "not env-a or env-b" in result.stderr and "not sealed" in result.stderr
    assert not (tmp_path / "ran").exists()


def test_a_failed_seal_fails_install(tmp_path) -> None:
    root = _box(tmp_path, "a")
    (root / "env-a" / "bin" / "boxmunge-server").write_text("#!/usr/bin/env bash\nexit 1\n")
    assert _run(root, "0").returncode == 1
