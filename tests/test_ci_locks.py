# SPDX-License-Identifier: Apache-2.0
"""CI's lock-install guard: every server lock file installs, hash-checked, on
Python 3.11 (the server's floor) and 3.12, not only on the 3.13 they are
compiled with (scripts/ci-lock-install.sh, the `locks` job)."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "ci-lock-install.sh"

# A python3 stand-in: `-m venv DIR` makes DIR/bin/pip, which logs its
# arguments and exits $PIP_RC.
FAKE_PYTHON = """#!/usr/bin/env bash
[[ "$1 $2" == "-m venv" ]] || { echo "unexpected: $*" >&2; exit 2; }
mkdir -p "$3/bin"
printf '#!/usr/bin/env bash\\necho "$*" >> "%s"\\nexit "${PIP_RC:-0}"\\n' "$PIP_LOG" > "$3/bin/pip"
chmod +x "$3/bin/pip"
"""


def _run(tmp_path: Path, pip_rc: int = 0) -> tuple[subprocess.CompletedProcess, list[str]]:
    python = tmp_path / "python3.11"
    python.write_text(FAKE_PYTHON)
    python.chmod(0o755)
    log = tmp_path / "pip.log"
    proc = subprocess.run(["bash", str(SCRIPT), str(python)], capture_output=True, text=True,
                          env={**os.environ, "PIP_LOG": str(log), "PIP_RC": str(pip_rc)})
    return proc, log.read_text().splitlines() if log.exists() else []


def _files(call: str) -> list[str]:
    return re.findall(r"-r (\S+)", call)


def test_every_server_lock_installs_with_hashes(tmp_path: Path) -> None:
    proc, calls = _run(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert all("--require-hashes" in call for call in calls), calls
    installed = {Path(f).name for call in calls for f in _files(call)}
    assert installed == {p.name for p in REPO.glob("requirements*.txt")}


def test_the_box_set_installs_together_as_the_shim_installs_it(tmp_path: Path) -> None:
    """One pip call for what a slot gets, so conflicting pins fail here."""
    _proc, calls = _run(tmp_path)
    shim = (REPO / "scripts" / "boxmunge-upgrade.d" / "release.sh").read_text()
    slot = re.search(r"^PINNED_REQUIREMENTS=\(([^)]*)\)", shim, re.M)[1].split()
    assert set(slot) <= {Path(f).name for f in _files(calls[0])}


def test_a_failing_install_fails_the_guard(tmp_path: Path) -> None:
    proc, calls = _run(tmp_path, pip_rc=1)
    assert proc.returncode != 0
    assert len(calls) == 1


@pytest.fixture(scope="module")
def ci() -> dict:
    return yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())


def test_the_locks_job_installs_on_311_and_312_on_every_change(ci: dict) -> None:
    job = ci["jobs"]["locks"]
    assert "if" not in job
    setup = next(s for s in job["steps"] if "setup-python" in (s.get("uses") or ""))
    assert setup["with"]["python-version"].split() == ["3.11", "3.12"]
    runs = [s.get("run") or "" for s in job["steps"]]
    assert "bash scripts/ci-lock-install.sh python3.11 python3.12" in runs
    assert all("if" not in s for s in job["steps"])
    assert "locks" in ci["jobs"]["ci-ok"]["needs"]
