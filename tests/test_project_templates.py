# SPDX-License-Identifier: Apache-2.0
"""templates/project/ tells the truth: its scripts are POSIX sh that boxmunge
can run, and every boxmunge command it names exists."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from boxmunge import cli

TEMPLATES = Path(__file__).resolve().parents[1] / "templates" / "project"
SCRIPTS = sorted((TEMPLATES / "boxmunge-scripts").iterdir())


def _shells() -> list[str]:
    return [s for s in (shutil.which("dash"), "/bin/sh") if s]


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
@pytest.mark.parametrize("shell", _shells())
def test_scripts_are_posix_sh(script: Path, shell: str) -> None:
    """smoke.sh runs as `sh <script>` in the container, whose sh may be dash or busybox."""
    text = script.read_text()
    assert text.startswith("#!/bin/sh\n"), script.name
    assert "pipefail" not in text and "[[" not in text, script.name
    subprocess.run([shell, "-n", str(script)], check=True)


@pytest.mark.parametrize("shell", _shells())
def test_unconfigured_smoke_is_a_one_line_warning(shell: str) -> None:
    result = subprocess.run([shell, str(TEMPLATES / "boxmunge-scripts" / "smoke.sh"), "web"],
                            capture_output=True, text=True)
    assert result.returncode == 1, "exit 2 would stop every container of the project"
    assert len([ln for ln in result.stderr.splitlines() if ln.strip()]) == 1


@pytest.mark.parametrize("name", ["README.md", "project.env.example"])
def test_named_commands_exist(name: str) -> None:
    text = (TEMPLATES / name).read_text()
    named = set(re.findall(r"(?m)(?:^[#\s]*|`)boxmunge ([a-z][a-z-]*)\b", text))
    assert named, f"{name} names no command; update this test"
    assert named <= set(cli.COMMANDS), f"{name} names unknown commands: {named - set(cli.COMMANDS)}"
