# SPDX-License-Identifier: Apache-2.0
"""install.sh runs the cosign and Trivy installs before bootstrap/init-host.sh,
which is what installs gnupg. Debian cloud images no longer ship gnupg, so
the installer must ensure what those installs use before the first use."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = (REPO / "install.sh").read_text()


def _function_body(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", SCRIPT, re.M | re.S)
    assert m, f"{name} not found in install.sh"
    return m.group(0)


def _first_call(name: str) -> int:
    m = re.search(rf"^{name}$", SCRIPT, re.M)
    assert m, f"no top-level call of {name} in install.sh"
    return m.start()


def test_prereqs_are_ensured_before_the_first_gpg_use() -> None:
    gpg_use = re.search(r"\|\s*gpg\b", SCRIPT)
    assert gpg_use, "install.sh no longer uses gpg; drop this test if so"
    assert _first_call("ensure_install_prereqs") < _first_call("install_cosign")
    assert _first_call("ensure_install_prereqs") < _first_call("install_trivy")
    assert _first_call("ensure_install_prereqs") < gpg_use.start()
    assert _first_call("install_trivy") < SCRIPT.index("bootstrap/init-host.sh\" \"$@\"")


def _run_prereqs(tmp: Path, *, have_gpg: bool, apt_exit: int = 0) -> tuple[subprocess.CompletedProcess, str]:
    """Run the real function against stub apt-get/dpkg-query/curl on a PATH
    holding nothing else but grep, so what is 'installed' is controlled."""
    bin_dir = tmp / "bin"
    bin_dir.mkdir()
    log = tmp / "apt.log"
    (bin_dir / "grep").symlink_to(shutil.which("grep"))
    stubs = {
        "apt-get": f'echo "$*" >> {log}\nexit {apt_exit}\n',
        "dpkg-query": "echo installed\n",  # ca-certificates present
        "curl": "exit 0\n",
    }
    if have_gpg:
        stubs["gpg"] = "exit 0\n"
    for name, body in stubs.items():
        (bin_dir / name).write_text("#!/bin/sh\n" + body)
        (bin_dir / name).chmod(0o755)
    script = tmp / "run.sh"
    script.write_text("set -euo pipefail\n" + _function_body("ensure_install_prereqs")
                      + "ensure_install_prereqs\n")
    proc = subprocess.run([shutil.which("bash"), str(script)], env={"PATH": str(bin_dir)},
                          capture_output=True, text=True)
    return proc, log.read_text() if log.exists() else ""


def test_missing_gpg_installs_gnupg_after_an_apt_update(tmp_path: Path) -> None:
    proc, log = _run_prereqs(tmp_path, have_gpg=False)
    assert proc.returncode == 0, proc.stderr
    lines = log.splitlines()
    assert lines[0].startswith("update")
    assert re.search(r"^install .*\bgnupg\b", lines[1])
    assert "curl" not in lines[1]


def test_nothing_is_installed_when_the_prerequisites_are_present(tmp_path: Path) -> None:
    proc, log = _run_prereqs(tmp_path, have_gpg=True)
    assert proc.returncode == 0, proc.stderr
    assert log == ""


def test_a_failed_prerequisite_install_stops_the_installer(tmp_path: Path) -> None:
    proc, _ = _run_prereqs(tmp_path, have_gpg=False, apt_exit=100)
    assert proc.returncode != 0
