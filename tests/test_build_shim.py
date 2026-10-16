# SPDX-License-Identifier: Apache-2.0
"""The release build inlines the upgrade shim's libraries (scripts/build-shim.py).

Every installer of the shim on a box, including older releases' shims during
the upgrade hop, copies only scripts/boxmunge-upgrade, so the bundle must
carry it self-contained, built the same way every time.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "scripts" / "boxmunge-upgrade"
LIBS = sorted((REPO / "scripts" / "boxmunge-upgrade.d").glob("*.sh"))


def _build(source: Path, out: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO / "scripts" / "build-shim.py"), str(source), str(out)],
        capture_output=True, text=True, check=False,
    )


def test_build_is_deterministic(tmp_path: Path) -> None:
    assert _build(SOURCE, tmp_path / "one").returncode == 0
    assert _build(SOURCE, tmp_path / "two").returncode == 0
    assert (tmp_path / "one").read_bytes() == (tmp_path / "two").read_bytes()


def test_built_shim_is_self_contained(tmp_path: Path) -> None:
    out = tmp_path / "boxmunge-upgrade"
    assert _build(SOURCE, out).returncode == 0
    built = out.read_text()
    assert not re.search(r"^# >>> boxmunge-upgrade\.d:", built, re.M), "source loader left in the built shim"
    assert not re.search(r"^\s*(source|\.) ", built, re.M), "built shim sources another file"
    for lib in LIBS:
        for name in re.findall(r"^([a-z_]+)\(\) \{", lib.read_text(), re.M):
            assert f"\n{name}() {{" in built, f"{lib.name}:{name} not inlined"
    assert out.stat().st_mode & 0o111, "built shim is not executable"
    subprocess.run(["bash", "-n", str(out)], check=True)


def test_build_refuses_a_loader_that_misses_a_library(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    shutil.copytree(REPO / "scripts" / "boxmunge-upgrade.d", scripts / "boxmunge-upgrade.d")
    shutil.copy(SOURCE, scripts / "boxmunge-upgrade")
    (scripts / "boxmunge-upgrade.d" / "extra.sh").write_text("# shellcheck shell=bash\n")
    result = _build(scripts / "boxmunge-upgrade", tmp_path / "out")
    assert result.returncode != 0
    assert "extra" in result.stderr


@pytest.mark.parametrize("needle", [
    "python3 scripts/build-shim.py scripts/boxmunge-upgrade dist/.stage/boxmunge/scripts/boxmunge-upgrade",
    "rm -rf dist/.stage/boxmunge/scripts/boxmunge-upgrade.d",
])
def test_bundle_ships_the_built_shim(needle: str) -> None:
    assert needle in (REPO / "Makefile").read_text()


# The head of install.sh up to the first step that changes the system: the
# guard must sit in it. Only that head is ever run here, so a broken guard
# cannot let the rest of install.sh loose on the test machine.
_FIRST_STEP = "\n# ---------------------------------------------------------------------------\n# Docker Compose version."


def _install_head(tmp_path: Path, shim: Path) -> subprocess.CompletedProcess:
    install = (REPO / "install.sh").read_text()
    assert _FIRST_STEP in install, "install.sh layout changed; move this test's cut point"
    root = tmp_path / "bundle"
    (root / "scripts").mkdir(parents=True)
    (root / "install.sh").write_text(install.split(_FIRST_STEP)[0] + "\necho HEAD-COMPLETED\n")
    shutil.copy(shim, root / "scripts" / "boxmunge-upgrade")
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (fake / "id").write_text("#!/bin/sh\necho 0\n")  # pass the root check
    (fake / "id").chmod(0o755)
    return subprocess.run(
        ["bash", str(root / "install.sh")], capture_output=True, text=True, check=False,
        env={"PATH": f"{fake}:/usr/bin:/bin"},
    )


def test_install_sh_refuses_the_unbuilt_shim_up_front(tmp_path: Path) -> None:
    result = _install_head(tmp_path, SOURCE)
    assert result.returncode == 1
    assert "unbuilt source shim" in result.stderr and "release bundle" in result.stderr
    assert "HEAD-COMPLETED" not in result.stdout


def test_install_sh_accepts_the_built_shim(tmp_path: Path) -> None:
    built = tmp_path / "built"
    assert _build(SOURCE, built).returncode == 0
    result = _install_head(tmp_path, built)
    assert result.returncode == 0, result.stderr
    assert "HEAD-COMPLETED" in result.stdout
