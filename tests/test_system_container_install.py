# SPDX-License-Identifier: Apache-2.0
"""install.sh's boxmunge-system step (bootstrap/system-container.sh, and the
policy around it in install.sh).

The image is rebuilt when its definition changed since the last SUCCESSFUL
build, so a failed build is retried by the next run even though the new files
are already in place. A failed build stops a fresh install or an operator's
re-run; run by the upgrade shim it warns instead (the shim would blocklist the
release), keeps the previous container, and leaves the installer fingerprint
unrecorded so the next upgrade runs install.sh again."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "bootstrap" / "system-container.sh"
INSTALL_SH = (REPO / "install.sh").read_text()


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


class Box:
    """A boxmunge root with stub docker/id/chown on PATH. `build_rc` and
    `container` say how the stub docker answers."""

    def __init__(self, tmp: Path) -> None:
        self.tmp, self.root, self.bin = tmp, tmp / "root", tmp / "bin"
        self.bin.mkdir()
        self.log = tmp / "docker.log"
        self.build_rc, self.container = 0, False
        _stub(self.bin / "id", 'echo 1000\n')
        _stub(self.bin / "chown", "exit 0\n")
        _stub(self.bin / "docker",
              f'case "$1" in\n'
              f'  inspect) test -f {tmp}/container ;;\n'
              f'  compose) echo "$*" >> {self.log}; rc=$(cat {tmp}/build_rc);'
              f' [ "$rc" = 0 ] && touch {tmp}/container; exit "$rc" ;;\n'
              f'  *) exit 99 ;;\nesac\n')
        if shutil.which("sha256sum") is None:  # coreutils; macOS dev hosts lack it
            (self.bin / "sha256sum").write_text(
                f"#!{sys.executable}\nimport hashlib, sys\n"
                "print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest() + '  -')\n")
            (self.bin / "sha256sum").chmod(0o755)
        bundle = tmp / "bundle"
        (bundle / "bootstrap").mkdir(parents=True)
        shutil.copy(SCRIPT, bundle / "bootstrap" / SCRIPT.name)
        shutil.copytree(REPO / "system", bundle / "system")
        self.bundle = bundle

    def run(self) -> subprocess.CompletedProcess:
        (self.tmp / "build_rc").write_text(str(self.build_rc))
        if self.container:
            (self.tmp / "container").touch()
        else:
            (self.tmp / "container").unlink(missing_ok=True)
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "BOXMUNGE_ROOT": str(self.root)}
        return subprocess.run([shutil.which("bash"), str(self.bundle / "bootstrap" / SCRIPT.name)],
                              env=env, capture_output=True, text=True)

    def builds(self) -> int:
        return self.log.read_text().count("up -d --build") if self.log.exists() else 0


@pytest.fixture
def box(tmp_path: Path) -> Box:
    return Box(tmp_path)


def test_first_run_installs_the_definition_and_builds(box: Box) -> None:
    proc = box.run()
    assert proc.returncode == 0, proc.stderr
    assert box.builds() == 1
    dest = box.root / "system"
    assert (dest / "Dockerfile").read_bytes() == (REPO / "system" / "Dockerfile").read_bytes()
    assert (dest / "compose.yml").exists()
    assert (dest / ".env").read_text() == (
        f"BOXMUNGE_UID=1000\nBOXMUNGE_GID=1000\nBOXMUNGE_CONFIG={box.root}/config\n"
        f"BOXMUNGE_PROJECTS={box.root}/projects\n")


def test_unchanged_definition_with_a_container_is_left_alone(box: Box) -> None:
    box.run()
    box.container = True
    assert box.run().returncode == 0
    assert box.builds() == 1


def test_a_changed_dockerfile_rebuilds(box: Box) -> None:
    box.run()
    box.container = True
    with (box.bundle / "system" / "Dockerfile").open("a") as f:
        f.write("# bumped\n")
    assert box.run().returncode == 0
    assert box.builds() == 2


def test_a_missing_container_rebuilds(box: Box) -> None:
    box.run()
    box.container = False
    assert box.run().returncode == 0
    assert box.builds() == 2


def test_a_failed_build_fails_and_the_next_run_retries_it(box: Box) -> None:
    """The previous container is still running after a failed build, and the
    new files are already in place: only the build record says to retry."""
    box.run()
    with (box.bundle / "system" / "Dockerfile").open("a") as f:
        f.write("# bumped\n")
    box.container, box.build_rc = True, 1
    assert box.run().returncode != 0
    box.build_rc = 0
    assert box.run().returncode == 0
    assert box.builds() == 3


# --- install.sh's policy -----------------------------------------------------

def _function_body(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", INSTALL_SH, re.M | re.S)
    assert m, f"{name} not found in install.sh"
    return m.group(0)


def _policy(tmp: Path, *, from_shim: int, script_rc: int) -> subprocess.CompletedProcess:
    (tmp / "bootstrap").mkdir()
    (tmp / "bootstrap" / "system-container.sh").write_text(f"exit {script_rc}\n")
    script = tmp / "run.sh"
    script.write_text(
        "set -euo pipefail\n"
        f"SCRIPT_DIR={tmp}\nBOXMUNGE_ROOT={tmp}/root\nFROM_UPGRADE_SHIM={from_shim}\n"
        "SYSTEM_IMAGE_STALE=0\n"
        + _function_body("refresh_system_container")
        + 'refresh_system_container\necho "stale=${SYSTEM_IMAGE_STALE}"\n')
    return subprocess.run([shutil.which("bash"), str(script)], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin"})


def test_a_failed_build_stops_a_fresh_install_or_an_operator_rerun(tmp_path: Path) -> None:
    proc = _policy(tmp_path, from_shim=0, script_rc=1)
    assert proc.returncode != 0
    assert "stale=" not in proc.stdout
    assert "re-run the installer" in proc.stderr


def test_a_failed_build_under_the_upgrade_shim_warns_and_marks_the_image_stale(tmp_path: Path) -> None:
    proc = _policy(tmp_path, from_shim=1, script_rc=1)
    assert proc.returncode == 0, proc.stderr
    assert "stale=1" in proc.stdout
    assert "WARNING" in proc.stderr


@pytest.mark.parametrize("from_shim", [0, 1])
def test_a_successful_build_is_not_stale(tmp_path: Path, from_shim: int) -> None:
    proc = _policy(tmp_path, from_shim=from_shim, script_rc=0)
    assert proc.returncode == 0, proc.stderr
    assert "stale=0" in proc.stdout


def test_a_stale_image_leaves_the_installer_fingerprint_unrecorded() -> None:
    """So the upgrade shim runs install.sh, and so the build, again next time."""
    write = INSTALLER_WRITE.search(INSTALL_SH)
    assert write, "install.sh no longer records the installer fingerprint"
    guard = INSTALL_SH.rindex('if [[ "${SYSTEM_IMAGE_STALE}" -eq 1 ]]; then', 0, write.start())
    between = INSTALL_SH[guard:write.start()]
    assert "else" in between and "fi\n" not in between


INSTALLER_WRITE = re.compile(r'^\s*mv -f "\$\{INSTALLER_HASH_FILE\}\.tmp" "\$\{INSTALLER_HASH_FILE\}"$', re.M)
