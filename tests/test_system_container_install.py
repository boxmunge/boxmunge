# SPDX-License-Identifier: Apache-2.0
"""install.sh's boxmunge-system step (bootstrap/system-container.sh, and the
policy around it in install.sh).

The image is rebuilt unless the running one carries the installed definition
in its label, so a failed build is retried by the next run even though the
new files are already in place, and a rebuild by hand counts. A build is
tried three times. A failed build is recorded and the rest of the install
carries on; a fresh install or an operator's re-run then stops at the end,
naming the rebuild. Run by the upgrade shim it only warns (the shim would
blocklist the release), keeps the previous container, and leaves the
installer fingerprint unrecorded so the next upgrade runs install.sh again."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.system_container import system_definition

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "bootstrap" / "system-container.sh"
INSTALL_SH = (REPO / "install.sh").read_text()


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


class Box:
    """A boxmunge root with stub docker/id/chown/sleep on PATH. The stub
    container's image label lives in `label` (absent: no container); a build
    fails `fail_builds` times, then labels the image from .env."""

    def __init__(self, tmp: Path) -> None:
        self.tmp, self.root, self.bin = tmp, tmp / "root", tmp / "bin"
        self.bin.mkdir()
        self.log, self.label, self.fails = tmp / "docker.log", tmp / "label", tmp / "fails"
        self.fail_builds = 0
        _stub(self.bin / "id", 'echo 1000\n')
        _stub(self.bin / "chown", "exit 0\n")
        _stub(self.bin / "sleep", f'echo "sleep $1" >> {self.log}\n')
        env_file = self.root / "system" / ".env"
        _stub(self.bin / "docker",
              f'case "$1" in\n'
              f'  inspect) cat {self.label} 2>/dev/null ;;\n'
              f'  compose) echo "$*" >> {self.log}\n'
              f'    case "$*" in *--build*) ;; *) exit 0 ;; esac\n'
              f'    n=$(cat {self.fails}); if [ "$n" -gt 0 ]; then echo $((n - 1)) > {self.fails}; exit 1; fi\n'
              f'    sed -n "s/^BOXMUNGE_SYSTEM_DEFINITION=//p" {env_file} > {self.label} ;;\n'
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
        self.fails.write_text(str(self.fail_builds))
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "BOXMUNGE_ROOT": str(self.root)}
        return subprocess.run([shutil.which("bash"), str(self.bundle / "bootstrap" / SCRIPT.name)],
                              env=env, capture_output=True, text=True)

    def calls(self, needle: str) -> int:
        return self.log.read_text().count(needle) if self.log.exists() else 0


@pytest.fixture
def box(tmp_path: Path) -> Box:
    return Box(tmp_path)


def test_first_run_installs_the_definition_and_builds(box: Box) -> None:
    proc = box.run()
    assert proc.returncode == 0, proc.stderr
    assert box.calls("up -d --build") == 1
    dest = box.root / "system"
    assert (dest / "Dockerfile").read_bytes() == (REPO / "system" / "Dockerfile").read_bytes()
    definition = system_definition(BoxPaths(root=box.root))
    assert (dest / ".env").read_text() == (
        f"BOXMUNGE_UID=1000\nBOXMUNGE_GID=1000\nBOXMUNGE_CONFIG={box.root}/config\n"
        f"BOXMUNGE_PROJECTS={box.root}/projects\nBOXMUNGE_SYSTEM_DEFINITION={definition}\n")
    # The script and `health` (system_container.stale_image) agree on it.
    assert box.label.read_text().strip() == definition


def test_an_image_of_this_definition_is_started_not_rebuilt(box: Box) -> None:
    box.run()
    assert box.run().returncode == 0
    assert box.calls("up -d --build") == 1
    assert box.calls("up -d") == 2


def test_a_changed_dockerfile_rebuilds(box: Box) -> None:
    box.run()
    with (box.bundle / "system" / "Dockerfile").open("a") as f:
        f.write("# bumped\n")
    assert box.run().returncode == 0
    assert box.calls("up -d --build") == 2


def test_a_container_built_by_an_older_install_rebuilds(box: Box) -> None:
    box.label.write_text("\n")  # no label: built before this check existed
    assert box.run().returncode == 0
    assert box.calls("up -d --build") == 1


def test_a_transient_build_failure_is_retried(box: Box) -> None:
    box.fail_builds = 2
    proc = box.run()
    assert proc.returncode == 0, proc.stderr
    assert box.calls("up -d --build") == 3
    assert box.calls("sleep ") == 2


def test_a_failed_build_fails_and_the_next_run_retries_it(box: Box) -> None:
    """The previous container keeps running on its old label after a failed
    build, and the new files are already in place."""
    box.run()
    with (box.bundle / "system" / "Dockerfile").open("a") as f:
        f.write("# bumped\n")
    box.fail_builds = 3
    proc = box.run()
    assert proc.returncode != 0
    assert "failed 3 times" in proc.stderr
    box.fail_builds = 0
    assert box.run().returncode == 0
    assert box.calls("up -d --build") == 1 + 3 + 1


# --- install.sh's policy -----------------------------------------------------

def _function_body(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", INSTALL_SH, re.M | re.S)
    assert m, f"{name} not found in install.sh"
    return m.group(0)


def _policy(tmp: Path, *, from_shim: int, script_rc: int) -> subprocess.CompletedProcess:
    """Run the build step, a stand-in for the rest of the install, and the
    final check, as install.sh orders them."""
    (tmp / "bootstrap").mkdir()
    (tmp / "bootstrap" / "system-container.sh").write_text(f"exit {script_rc}\n")
    shutil.copy(REPO / "bootstrap" / "installer-fingerprint.sh", tmp / "bootstrap")
    fingerprint = tmp / "root" / "upgrade-root" / "installer.sha256"
    fingerprint.parent.mkdir(parents=True, mode=0o700)
    fingerprint.write_text("0" * 64 + "\n")
    script = tmp / "run.sh"
    script.write_text(
        "set -euo pipefail\n"
        f"SCRIPT_DIR={tmp}\nBOXMUNGE_ROOT={tmp / 'root'}\nFROM_UPGRADE_SHIM={from_shim}\n"
        "SYSTEM_IMAGE_STALE=0\n"
        'SYSTEM_REBUILD="sudo docker compose -f /opt/boxmunge/system/compose.yml up -d --build"\n'
        + _function_body("refresh_system_container")
        + _function_body("fail_if_system_image_stale")
        + 'refresh_system_container\necho "rest of the install"\n'
        + 'fail_if_system_image_stale\necho "stale=${SYSTEM_IMAGE_STALE}"\n')
    return subprocess.run([shutil.which("bash"), str(script)], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin"})


REBUILD = "sudo docker compose -f /opt/boxmunge/system/compose.yml up -d --build"


def test_a_failed_build_finishes_a_fresh_install_then_fails_it(tmp_path: Path) -> None:
    proc = _policy(tmp_path, from_shim=0, script_rc=1)
    assert proc.returncode == 1
    assert "rest of the install" in proc.stdout and "stale=" not in proc.stdout
    error = proc.stderr[proc.stderr.index("ERROR"):]
    assert REBUILD in error and "boxmunge doctor" in error
    # Forgotten before the exit, so the next upgrade re-runs install.sh.
    assert not (tmp_path / "root" / "upgrade-root" / "installer.sha256").exists()


def test_a_failed_build_under_the_upgrade_shim_warns_and_marks_the_image_stale(tmp_path: Path) -> None:
    proc = _policy(tmp_path, from_shim=1, script_rc=1)
    assert proc.returncode == 0, proc.stderr
    assert "stale=1" in proc.stdout
    assert "WARNING" in proc.stderr and REBUILD in proc.stderr and "ERROR" not in proc.stderr
    assert not (tmp_path / "root" / "upgrade-root" / "installer.sha256").exists()


@pytest.mark.parametrize("from_shim", [0, 1])
def test_a_successful_build_is_not_stale(tmp_path: Path, from_shim: int) -> None:
    proc = _policy(tmp_path, from_shim=from_shim, script_rc=0)
    assert proc.returncode == 0, proc.stderr
    assert "stale=0" in proc.stdout
    assert (tmp_path / "root" / "upgrade-root" / "installer.sha256").exists()


def test_the_install_fails_after_everything_else_and_before_the_fingerprint() -> None:
    final = INSTALL_SH.index("\nfail_if_system_image_stale\n")
    assert INSTALL_SH.index("\nrefresh_system_container\n") < final
    for step in ('install-sudoers\n', "systemctl enable --now", 'install-docs "${SCRIPT_DIR}/on-server"'):
        assert INSTALL_SH.index(step) < final, step
    assert final < INSTALLER_WRITE.search(INSTALL_SH).start()
    assert final < INSTALL_SH.index('installed successfully"\n')


def test_a_stale_image_leaves_the_installer_fingerprint_unrecorded() -> None:
    """So the upgrade shim runs install.sh, and so the build, again next time."""
    write = INSTALLER_WRITE.search(INSTALL_SH)
    assert write, "install.sh no longer records the installer fingerprint"
    guard = INSTALL_SH.rindex('if [[ "${SYSTEM_IMAGE_STALE}" -eq 0 ]]; then', 0, write.start())
    assert "fi\n" not in INSTALL_SH[guard:write.start()]


INSTALLER_WRITE = re.compile(r'^\s*BOXMUNGE_ROOT=\S+ bash "\$\{SCRIPT_DIR\}/bootstrap/installer-fingerprint\.sh" record ', re.M)
