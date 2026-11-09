# SPDX-License-Identifier: Apache-2.0
"""bootstrap/venv-deps.sh: install.sh's hash-pinned dependency install.

An upgrade is run by the box's current shim. Up to 0.10.1 that shim built the
new release's venv without requirements-mcp.txt, so the box came up without
MCP. It does run the new release's install.sh --upgrade-shim between that
build and the swap, and install.sh then completes the standby here. The
script runs for real against a throwaway root; only pip, which would reach
the network, is a stand-in that records its arguments.
"""
from __future__ import annotations

import os
import re
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
    """A 1.5.0 bundle, and a root whose live slot a runs 1.4.0 while the shim
    has just built 1.5.0 into slot b."""
    bundle = tmp_path / "bundle"
    (bundle / "bootstrap").mkdir(parents=True)
    shutil.copy(REPO / "bootstrap" / "venv-deps.sh", bundle / "bootstrap" / "venv-deps.sh")
    (bundle / "pyproject.toml").write_text('[project]\nname = "boxmunge-server"\nversion = "1.5.0"\n')
    for name in REQUIREMENTS:
        (bundle / name).write_text(f"{name}==1 --hash=sha256:{'0' * 64}\n")
    root = tmp_path / "root"
    for slot, version in (("a", "1.4.0"), ("b", "1.5.0+abc1234")):
        _stub(root / f"env-{slot}" / "bin" / "pip", f'echo "{slot} $*" >> "{tmp_path}/pip.log"\n')
        _stub(root / f"env-{slot}" / "bin" / "boxmunge-server",
              f'[[ "$1" != --version ]] || echo "boxmunge {version}"\n')
    (root / "env-active").symlink_to(root / "env-a")
    return tmp_path


def _run(box: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(box / "bundle" / "bootstrap" / "venv-deps.sh"), *args],
        env={**os.environ, "BOXMUNGE_ROOT": str(box / "root")},
        capture_output=True, text=True, check=False,
    )


def _pip_calls(box: Path) -> list[str]:
    log = box / "pip.log"
    return log.read_text().splitlines() if log.exists() else []


def test_standby_gets_every_pinned_file_and_the_live_slot_nothing(box: Path) -> None:
    result = _run(box, "standby")
    assert result.returncode == 0, result.stderr
    [call] = _pip_calls(box)
    assert call.startswith("b install ") and "--require-hashes" in call and "--no-cache-dir" in call
    for name in REQUIREMENTS:
        assert f"-r {box}/bundle/{name}" in call


def test_standby_follows_env_active(box: Path) -> None:
    root = box / "root"
    (root / "env-active").unlink()
    (root / "env-active").symlink_to(root / "env-b")
    _stub(root / "env-a" / "bin" / "boxmunge-server", 'echo "boxmunge 1.5.0"\n')
    assert _run(box, "standby").returncode == 0
    assert [c.split()[0] for c in _pip_calls(box)] == ["a"]


def test_a_standby_that_is_not_this_release_is_left_alone(box: Path) -> None:
    """During probation the standby is the previous release, a rollback's
    only target: installing this release's pins there could break it."""
    _stub(box / "root" / "env-b" / "bin" / "boxmunge-server", 'echo "boxmunge 1.4.0"\n')
    result = _run(box, "standby")
    assert result.returncode == 1
    assert "runs boxmunge '1.4.0', not this bundle's 1.5.0" in result.stderr
    assert _pip_calls(box) == []


def test_a_standby_that_does_not_run_is_left_alone(box: Path) -> None:
    shutil.rmtree(box / "root" / "env-b")
    result = _run(box, "standby")
    assert result.returncode == 1 and "runs boxmunge 'nothing'" in result.stderr
    assert _pip_calls(box) == []


@pytest.mark.parametrize("target", ["env-c", "elsewhere"])
def test_env_active_must_name_a_slot(box: Path, target: str) -> None:
    root = box / "root"
    (root / "env-active").unlink()
    (root / "env-active").symlink_to(root / target)
    result = _run(box, "standby")
    assert result.returncode == 1 and "not env-a or env-b" in result.stderr
    assert _pip_calls(box) == []


def test_a_bundle_without_a_pinned_file_installs_nothing(box: Path) -> None:
    (box / "bundle" / "requirements-mcp.txt").unlink()
    result = _run(box, "standby")
    assert result.returncode == 1
    assert "no hash-pinned requirements-mcp.txt; refusing an unpinned install" in result.stderr
    assert _pip_calls(box) == []


def test_a_pip_failure_exits_75(box: Path) -> None:
    """install.sh exits with it, so a shim that blocklists the failed
    install.sh records the cause: system_upgrade_failed: install_sh_exit_75."""
    _stub(box / "root" / "env-b" / "bin" / "pip", "exit 1\n")
    result = _run(box, "standby")
    assert result.returncode == 75
    assert "pip could not install the hash-pinned dependencies into" in result.stderr


def test_active_installs_into_env_active(box: Path) -> None:
    assert _run(box, "active").returncode == 0
    [call] = _pip_calls(box)
    assert call.startswith("a install ") and f"-r {box}/bundle/requirements-mcp.txt" in call


def test_the_release_version_line_is_the_form_standby_reads() -> None:
    """Releases are X.Y.Z (the cosign identity pins vX.Y.Z tags); standby
    mode reads the bundle's version from this one line."""
    lines = (REPO / "pyproject.toml").read_text().splitlines()
    assert len([line for line in lines if re.fullmatch(r'version = "\d+\.\d+\.\d+"', line)]) == 1


def test_usage(box: Path) -> None:
    result = _run(box)
    assert result.returncode == 1 and "usage: venv-deps.sh <active|standby>" in result.stderr


def test_install_sh_completes_the_standby_from_the_shim_and_never_env_active() -> None:
    """install.sh --upgrade-shim runs while env-active is still the previous
    release, the rollback target."""
    install = (REPO / "install.sh").read_text()
    start = install.index('if [[ "${FROM_UPGRADE_SHIM}" -eq 0 ]]; then\n')
    block = install[start:install.index("\nfi\n", start)]
    by_hand, from_shim = block.split("\nelse\n")
    assert 'bootstrap/venv-deps.sh" active' in by_hand
    assert from_shim.strip() == 'BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/venv-deps.sh" standby'
