# SPDX-License-Identifier: Apache-2.0
"""install.sh's install of the upgrade shim (install_shim).

When the upgrade shim runs install.sh after its own self-update refused the
bundle's shim, bin/boxmunge-upgrade is the running shim. bash reads a script
from its file as it goes, so a `cp` over that inode would hand the running
upgrade the new bytes part-way through. The shim is gated on `bash -n` and
renamed into place instead."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = (REPO / "install.sh").read_text()
BASH = shutil.which("bash")


def _install_shim_body() -> str:
    m = re.search(r"^install_shim\(\) \{\n.*?^\}\n", INSTALL_SH, re.M | re.S)
    assert m, "install_shim not found in install.sh"
    return m.group(0)


def _box(tmp: Path, bundle_shim: str) -> tuple[Path, Path]:
    (tmp / "bundle" / "scripts").mkdir(parents=True)
    (tmp / "bundle" / "scripts" / "boxmunge-upgrade").write_text(bundle_shim)
    (tmp / "root" / "bin").mkdir(parents=True)
    dest = tmp / "root" / "bin" / "boxmunge-upgrade"
    dest.write_text('#!/usr/bin/env bash\necho "old: start"\nsleep 1\necho "old: end"\n')
    dest.chmod(0o755)
    script = tmp / "run.sh"
    script.write_text(f"set -euo pipefail\nSCRIPT_DIR={tmp / 'bundle'}\nBOXMUNGE_ROOT={tmp / 'root'}\n"
                      + _install_shim_body() + "install_shim\n")
    return script, dest


def test_the_running_shim_keeps_its_own_bytes(tmp_path: Path) -> None:
    script, dest = _box(tmp_path, '#!/usr/bin/env bash\necho "new: start"\nsleep 1\n'
                                  'echo "NEW BYTES IN THE RUNNING SHIM"\n')
    inode = dest.stat().st_ino
    running = subprocess.Popen([BASH, str(dest)], stdout=subprocess.PIPE, text=True)
    time.sleep(0.3)  # it has read up to its sleep
    proc = subprocess.run([BASH, str(script)], capture_output=True, text=True)
    out, _ = running.communicate(timeout=10)
    assert proc.returncode == 0, proc.stderr
    assert out == "old: start\nold: end\n"
    assert dest.stat().st_ino != inode
    assert "NEW BYTES" in dest.read_text()
    assert dest.stat().st_mode & 0o777 == 0o755
    assert [p.name for p in dest.parent.iterdir()] == ["boxmunge-upgrade"]


def test_a_shim_that_fails_bash_n_is_refused_and_the_old_one_kept(tmp_path: Path) -> None:
    script, dest = _box(tmp_path, "#!/usr/bin/env bash\nif then\n")
    before, inode = dest.read_bytes(), dest.stat().st_ino
    proc = subprocess.run([BASH, str(script)], capture_output=True, text=True)
    assert proc.returncode == 1
    assert "has syntax errors" in proc.stderr and "Install another release" in proc.stderr
    assert dest.read_bytes() == before and dest.stat().st_ino == inode
    assert os.listdir(dest.parent) == ["boxmunge-upgrade"]


def test_install_sh_installs_the_shim_only_through_install_shim() -> None:
    assert "\ninstall_shim\n" in INSTALL_SH
    assert not re.search(r'^\s*cp [^\n]*scripts/boxmunge-upgrade"', INSTALL_SH, re.M)


# --- the version install.sh reports ----------------------------------------

def _version_block() -> str:
    """install.sh from INSTALLED_VERSION= to the end of the version record (the
    same span tests/integration/shim_hop.sh runs)."""
    m = re.search(r"^INSTALLED_VERSION=.*?^fi\n", INSTALL_SH, re.M | re.S)
    assert m, "the version block is not in install.sh"
    return m.group(0)


def _installed_version(tmp: Path, *, from_shim: int) -> tuple[str, str]:
    """(INSTALLED_VERSION, config/version) with env-active on 0.11.3, a bundle
    of 0.11.4, and config/version saying 0.11.2 to see whether it is written."""
    (tmp / "bundle").mkdir()
    (tmp / "bundle" / "pyproject.toml").write_text('[project]\nname = "boxmunge-server"\nversion = "0.11.4"\n')
    (tmp / "root" / "env-active" / "bin").mkdir(parents=True)
    (tmp / "root" / "config").mkdir()
    (tmp / "root" / "config" / "version").write_text("0.11.2\n")
    pip = tmp / "root" / "env-active" / "bin" / "pip"
    pip.write_text('#!/bin/sh\necho "Name: boxmunge-server"\necho "Version: 0.11.3"\n')
    pip.chmod(0o755)
    script = tmp / "run.sh"
    script.write_text(f"set -euo pipefail\nSCRIPT_DIR={tmp / 'bundle'}\nBOXMUNGE_ROOT={tmp / 'root'}\n"
                      f"FROM_UPGRADE_SHIM={from_shim}\n" + _version_block() + 'echo "${INSTALLED_VERSION}"\n')
    proc = subprocess.run([BASH, str(script)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip(), (tmp / "root" / "config" / "version").read_text().strip()


def test_run_by_the_shim_it_reports_the_bundle_version_not_the_live_one(tmp_path: Path) -> None:
    """The shim runs install.sh before its swap: env-active is still the
    previous release, so "boxmunge 0.11.3 installed successfully" was printed
    while 0.11.4 was being installed. The version record is the shim's."""
    assert _installed_version(tmp_path, from_shim=1) == ("0.11.4", "0.11.2")


def test_run_by_hand_it_reports_and_records_the_live_venv(tmp_path: Path) -> None:
    assert _installed_version(tmp_path, from_shim=0) == ("0.11.3", "0.11.3")
