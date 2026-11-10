"""install.sh (bootstrap/python-floor.sh) refuses a host whose python3 is
older than the server's floor.

Without the check, `python3 -m venv` succeeds on an older Python and the
hash-pinned install then fails halfway with a resolver error that does not
say what to do.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = (REPO / "install.sh").read_text()
FLOOR_SH = (REPO / "bootstrap" / "python-floor.sh").read_text()
FUNC_RE = re.compile(r"^require_python_floor\(\) \{\n.*?^\}\n", re.M | re.S)


def _run(tmp_path: Path, floor: str, with_python: bool = True) -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    if with_python:
        (bindir / "python3").symlink_to(sys.executable)
    func = FUNC_RE.search(FLOOR_SH)
    assert func, "bootstrap/python-floor.sh must define require_python_floor()"
    script = f'set -euo pipefail\nMIN_PYTHON="{floor}"\n{func.group(0)}require_python_floor\necho OK\n'
    return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True,
                          env={"PATH": str(bindir)})


def test_floor_matches_requires_python() -> None:
    meta = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]
    match = re.search(r'^MIN_PYTHON="([0-9.]+)"$', FLOOR_SH, re.M)
    assert match, "bootstrap/python-floor.sh must set MIN_PYTHON"
    assert meta["requires-python"] == f">={match.group(1)}"


def test_a_python_at_the_floor_passes(tmp_path: Path) -> None:
    floor = "%d.%d" % sys.version_info[:2]
    result = _run(tmp_path, floor)
    assert (result.returncode, result.stdout) == (0, "OK\n"), result


def test_an_older_python_is_refused_with_the_fix(tmp_path: Path) -> None:
    result = _run(tmp_path, "3.99")
    assert result.returncode == 1 and "OK" not in result.stdout, result
    found = "%d.%d.%d" % sys.version_info[:3]
    assert f"needs Python 3.99 or newer; this host's python3 is {found}" in result.stderr
    assert "Debian 13" in result.stderr


def test_a_host_without_python3_is_refused(tmp_path: Path) -> None:
    result = _run(tmp_path, "3.13", with_python=False)
    assert result.returncode == 1 and "OK" not in result.stdout, result
    assert "this host has no python3" in result.stderr


def test_checked_before_changes_and_after_the_bootstrap() -> None:
    """An upgrade (python3 always present) is refused before cosign, Trivy or
    the bootstrap touch the host; a fresh install whose image lacks python3 is
    checked once init-host.sh has installed it."""
    assert INSTALL_SH.index('source "${SCRIPT_DIR}/bootstrap/python-floor.sh"') < INSTALL_SH.index(
        "command -v python3 >/dev/null && require_python_floor")
    early = INSTALL_SH.index('command -v python3 >/dev/null && require_python_floor')
    assert early < INSTALL_SH.index('install_cosign "${HOST_ARCH}"')
    init = INSTALL_SH.index('bash "${SCRIPT_DIR}/bootstrap/init-host.sh" "$@"')
    assert INSTALL_SH.index("    require_python_floor\n", init) < INSTALL_SH.index("else", init)
