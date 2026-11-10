# SPDX-License-Identifier: Apache-2.0
"""bootstrap/cosign.sh: install.sh installs the cosign the upgrade shim
verifies releases with, pinned per architecture. Runs the real functions with
stub curl/sha256sum on PATH and the install target in a temp dir: the stub
sha256sum passes a file containing PINNED, standing in for the pinned binary.
The CI arm64 job installs and runs the real arm64 binary."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "bootstrap" / "cosign.sh"
INSTALL_SH = (REPO / "install.sh").read_text()


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


PINNED = 'echo "GitVersion:    v2.4.1"  # PINNED'


def _run(tmp: Path, call: str, *, existing: str | None = None,
         downloaded: str = PINNED) -> tuple[subprocess.CompletedProcess, Path]:
    """Source the library and run `call`. `existing` is the body of a cosign
    already at the install target; `downloaded` the body curl 'downloads'."""
    bin_dir, log = tmp / "bin", tmp / "calls.log"
    bin_dir.mkdir(parents=True)
    target = tmp / "usr-local-bin" / "cosign"
    target.parent.mkdir()
    if existing is not None:
        _stub(target, existing)
    payload = tmp / "payload"
    _stub(payload, downloaded)
    # curl ... <url> -o <file>: record the URL, write the payload to <file>.
    _stub(bin_dir / "curl", f'while [ $# -gt 0 ]; do case "$1" in https://*) echo "curl $1" >> {log} ;;'
                            f' -o) cp {payload} "$2"; shift ;; esac; shift; done\n')
    # sha256sum -c [--status] -: "<hash>  <file>" on stdin; record it, pass PINNED files.
    _stub(bin_dir / "sha256sum", f'read -r line; echo "sha256sum $line" >> {log}\n'
                                 'grep -q PINNED "${line#*  }"\n')
    script = tmp / "run.sh"
    script.write_text(f"set -euo pipefail\nsource {LIB}\nCOSIGN_BIN={target}\n{call}\n")
    proc = subprocess.run([shutil.which("bash"), str(script)], capture_output=True, text=True,
                          env={"PATH": f"{bin_dir}:/usr/bin:/bin"})
    return proc, log


def _pin(arch: str, tmp: Path) -> str:
    proc, _ = _run(tmp, f"cosign_sha256 {arch}")
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_each_supported_arch_has_a_pin(arch: str, tmp_path: Path) -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", _pin(arch, tmp_path))


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_the_signing_version_is_pinned_for_each_arch(arch: str, tmp_path: Path) -> None:
    """The CI rehearsal signs with COSIGN_SIGN_VERSION and verifies with both
    pins, on both architectures."""
    proc, _ = _run(tmp_path, f'cosign_sha256 {arch} "$COSIGN_SIGN_VERSION"; echo "$COSIGN_SIGN_VERSION"')
    assert proc.returncode == 0, proc.stderr
    sha, version = proc.stdout.split()
    assert re.fullmatch(r"[0-9a-f]{64}", sha) and sha != _pin(arch, tmp_path / "box")
    assert re.fullmatch(r"v3\.\d+\.\d+", version)


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_install_takes_another_pinned_version(arch: str, tmp_path: Path) -> None:
    proc, _ = _run(tmp_path / "pin", f'cosign_sha256 {arch} "$COSIGN_SIGN_VERSION"; echo "$COSIGN_SIGN_VERSION"')
    pin, version = proc.stdout.split()
    proc, log = _run(tmp_path, f'install_cosign {arch} "$COSIGN_SIGN_VERSION"')
    assert proc.returncode == 0, proc.stderr
    calls = log.read_text()
    assert f"/{version}/cosign-linux-{arch}\n" in calls
    assert f"sha256sum {pin}  " in calls


def test_a_version_without_a_pin_is_refused(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "install_cosign amd64 v9.9.9")
    assert proc.returncode != 0
    assert "no cosign v9.9.9 pin" in proc.stderr
    assert not log.exists()


def test_other_archs_have_no_pin(tmp_path: Path) -> None:
    proc, _ = _run(tmp_path, "cosign_sha256 riscv64")
    assert proc.returncode != 0 and proc.stdout == ""


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_fresh_install_fetches_and_checks_the_arch_binary(arch: str, tmp_path: Path) -> None:
    pin = _pin(arch, tmp_path / "pin")
    proc, log = _run(tmp_path, f"install_cosign {arch}")
    assert proc.returncode == 0, proc.stderr
    calls = log.read_text()
    assert f"/v2.4.1/cosign-linux-{arch}\n" in calls
    assert f"sha256sum {pin}  " in calls
    assert (tmp_path / "usr-local-bin" / "cosign").exists()


def test_the_pinned_binary_already_installed_is_kept_without_running_it(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "install_cosign arm64", existing="exit 99  # PINNED")
    assert proc.returncode == 0, proc.stderr
    assert "curl" not in log.read_text()


def test_another_build_is_replaced_without_running_it(tmp_path: Path) -> None:
    """Installers before 0.11.4 put the amd64 cosign on arm64 hosts, where it
    cannot run (exit 126, exec format error). It is never run, only hashed."""
    ran = tmp_path / "old-cosign-ran"
    proc, log = _run(tmp_path, "install_cosign arm64", existing=f"touch {ran}; exit 126")
    assert proc.returncode == 0, proc.stderr
    assert "/cosign-linux-arm64\n" in log.read_text()
    assert "not the pinned cosign" in proc.stdout
    assert not ran.exists()


def test_a_download_that_does_not_match_the_pin_is_not_installed(tmp_path: Path) -> None:
    proc, _ = _run(tmp_path, "install_cosign amd64", downloaded='echo "GitVersion:    v2.4.1"')
    assert proc.returncode != 0
    assert not (tmp_path / "usr-local-bin" / "cosign").exists()


def test_the_download_is_removed_when_it_fails_its_check(tmp_path: Path) -> None:
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    proc, _ = _run(tmp_path, f"export TMPDIR={tmpdir}\ninstall_cosign amd64",
                   downloaded='echo "GitVersion:    v2.4.1"')
    assert proc.returncode != 0
    assert list(tmpdir.iterdir()) == []


def test_an_installed_binary_that_does_not_run_fails_the_install(tmp_path: Path) -> None:
    proc, _ = _run(tmp_path, "install_cosign arm64", downloaded="exit 126  # PINNED")
    assert proc.returncode != 0
    assert "does not run" in proc.stderr


def test_an_arch_without_a_pin_is_refused(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "install_cosign riscv64")
    assert proc.returncode != 0
    assert "riscv64" in proc.stderr
    assert not log.exists()


def test_install_sh_refuses_an_unsupported_arch_before_changing_anything() -> None:
    """The arch check sits in the pre-flight, before the first step that
    changes the host (the CrowdSec apt source repair)."""
    check = INSTALL_SH.index('cosign_sha256 "${HOST_ARCH}"')
    assert check < INSTALL_SH.index("\nremove_dead_crowdsec_repo\n")
    assert re.search(r'^HOST_ARCH="\$\(dpkg --print-architecture\)"$', INSTALL_SH, re.M)
    assert re.search(r'^install_cosign "\$\{HOST_ARCH\}"$', INSTALL_SH, re.M)
