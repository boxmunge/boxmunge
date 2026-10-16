# SPDX-License-Identifier: Apache-2.0
"""Run the upgrade-shim shell tests as part of the unit suite.

The root upgrade shim is bash, so its tests are bash too. Running them here
means `make test` and CI exercise them instead of relying on someone
remembering to run the scripts by hand.

Each script runs twice: against the source shim (which sources
scripts/boxmunge-upgrade.d/) and against the self-contained shim that
scripts/build-shim.py builds for releases, which is what boxes run.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent
SCRIPTS = sorted([TESTS / "test_boxmunge_upgrade_shim.sh", *(TESTS / "shim").glob("test_*.sh")])


@pytest.fixture(scope="module")
def built_shim(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("built") / "boxmunge-upgrade"
    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "build-shim.py"),
         str(REPO / "scripts" / "boxmunge-upgrade"), str(out)],
        check=True,
    )
    return out


def test_shim_scripts_discovered() -> None:
    assert len(SCRIPTS) >= 2


@pytest.mark.parametrize("variant", ["source", "built"])
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_shim_script_passes(script: Path, variant: str, built_shim: Path) -> None:
    shim = REPO / "scripts" / "boxmunge-upgrade" if variant == "source" else built_shim
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, timeout=600,
        env={**os.environ, "SHIM_UNDER_TEST": str(shim)},
    )
    failures = [line for line in result.stdout.splitlines() if line.startswith("FAIL")]
    assert result.returncode == 0, (
        f"{script.name} ({variant}) failed:\n" + "\n".join(failures) + "\n" + result.stderr[-2000:]
    )
