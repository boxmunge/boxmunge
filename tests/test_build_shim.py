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
