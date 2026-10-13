# SPDX-License-Identifier: Apache-2.0
"""Run the upgrade-shim shell tests as part of the unit suite.

The root upgrade shim is bash, so its tests are bash too. Running them here
means `make test` and CI exercise them instead of relying on someone
remembering to run the scripts by hand.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
SCRIPTS = sorted([TESTS / "test_boxmunge_upgrade_shim.sh", *(TESTS / "shim").glob("test_*.sh")])


def test_shim_scripts_discovered() -> None:
    assert len(SCRIPTS) >= 2


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_shim_script_passes(script: Path) -> None:
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, timeout=300,
    )
    failures = [line for line in result.stdout.splitlines() if line.startswith("FAIL")]
    assert result.returncode == 0, (
        f"{script.name} failed:\n" + "\n".join(failures) + "\n" + result.stderr[-2000:]
    )
