# SPDX-License-Identifier: Apache-2.0
"""bootstrap/venv-deps.sh: install.sh's hash-pinned dependency install.

install.sh run by hand (a fresh install, or a re-run) installs the bundle's
dependencies into env-active. Run by the upgrade shim it touches no venv: the
shim built the standby itself, and env-active is the rollback target. The
script runs for real against a throwaway root; only pip, which would reach
the network, is a stand-in that records its arguments.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
REQUIREMENTS = ["requirements-build.txt", "requirements-tui.txt", "requirements-mcp.txt"]


def _stub(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)


@pytest.fixture
def box(tmp_path: Path) -> Path:
    """A bundle, and a root with both slots, a live."""
    bundle = tmp_path / "bundle"
    (bundle / "bootstrap").mkdir(parents=True)
    shutil.copy(REPO / "bootstrap" / "venv-deps.sh", bundle / "bootstrap" / "venv-deps.sh")
    for name in REQUIREMENTS:
        (bundle / name).write_text(f"{name}==1 --hash=sha256:{'0' * 64}\n")
    root = tmp_path / "root"
    for slot in ("a", "b"):
        _stub(root / f"env-{slot}" / "bin" / "pip", f'echo "{slot} $*" >> "{tmp_path}/pip.log"\n')
    (root / "env-active").symlink_to(root / "env-a")
    return tmp_path


def _run(box: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(box / "bundle" / "bootstrap" / "venv-deps.sh")],
        env={**os.environ, "BOXMUNGE_ROOT": str(box / "root")},
        capture_output=True, text=True, check=False,
    )


def _pip_calls(box: Path) -> list[str]:
    log = box / "pip.log"
    return log.read_text().splitlines() if log.exists() else []


def test_env_active_gets_every_pinned_file_and_the_other_slot_nothing(box: Path) -> None:
    result = _run(box)
    assert result.returncode == 0, result.stderr
    [call] = _pip_calls(box)
    assert call.startswith("a install ") and "--require-hashes" in call and "--no-cache-dir" in call
    for name in REQUIREMENTS:
        assert f"-r {box}/bundle/{name}" in call


def test_a_bundle_without_a_pinned_file_installs_nothing(box: Path) -> None:
    (box / "bundle" / "requirements-mcp.txt").unlink()
    result = _run(box)
    assert result.returncode == 1
    assert "no hash-pinned requirements-mcp.txt; refusing an unpinned install" in result.stderr
    assert _pip_calls(box) == []


def test_a_pip_failure_fails_the_install(box: Path) -> None:
    _stub(box / "root" / "env-a" / "bin" / "pip", "exit 1\n")
    result = _run(box)
    assert result.returncode == 1
    assert "pip could not install the hash-pinned dependencies into" in result.stderr


def test_install_sh_run_by_the_shim_touches_no_venv() -> None:
    """install.sh --upgrade-shim runs while env-active is still the previous
    release, the rollback target, and the shim has built the standby."""
    install = (REPO / "install.sh").read_text()
    assert install.count("venv-deps.sh\"") == 1 and install.count("/bin/pip\" install") == 1
    start = install.index('if [[ "${FROM_UPGRADE_SHIM}" -eq 0 ]]; then\n')
    by_hand = install[start:install.index("\nfi\n", start)]
    assert 'bootstrap/venv-deps.sh"\n' in by_hand and '/env-active/bin/pip" install' in by_hand
    assert "\nelse\n" not in by_hand
