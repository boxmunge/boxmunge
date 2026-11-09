# SPDX-License-Identifier: Apache-2.0
"""system/Dockerfile picks the age and rclone release assets, and their pinned
SHA256s, for the architecture BuildKit builds for (TARGETARCH), and fails the
build for any other. Runs the Dockerfile's own `case` under sh with the ARG
values it declares; the CI arm64 job builds the real image on arm64."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

DOCKERFILE = (Path(__file__).resolve().parents[1] / "system" / "Dockerfile").read_text()


def _args() -> dict[str, str]:
    return dict(re.findall(r"^ARG (\w+)=(\S+)\s*$", DOCKERFILE, re.M))


def _select(target_arch: str) -> subprocess.CompletedProcess:
    """Run the Dockerfile's arch `case` and print what it selected."""
    run = DOCKERFILE.replace("\\\n", " ")
    m = re.search(r'case "\$\{TARGETARCH\}" in .*? esac', run)
    assert m, "system/Dockerfile has no case on ${TARGETARCH}"
    env = {**_args(), "TARGETARCH": target_arch, "PATH": "/usr/bin:/bin"}
    script = m.group(0) + '\necho "${age_sha256} ${rclone_sha256}"\n'
    return subprocess.run([shutil.which("sh"), "-euc", script], env=env,
                          capture_output=True, text=True)


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_each_supported_arch_gets_its_own_pins(arch: str) -> None:
    proc = _select(arch)
    assert proc.returncode == 0, proc.stderr
    args = _args()
    suffix = arch.upper()
    assert proc.stdout.split() == [args[f"AGE_SHA256_{suffix}"], args[f"RCLONE_SHA256_{suffix}"]]


def test_the_two_archs_have_different_pins() -> None:
    assert _select("amd64").stdout != _select("arm64").stdout


@pytest.mark.parametrize("arch", ["riscv64", "arm", "386"])
def test_any_other_arch_fails_the_build(arch: str) -> None:
    proc = _select(arch)
    assert proc.returncode != 0
    assert arch in proc.stderr and "amd64" in proc.stderr and "arm64" in proc.stderr


def test_a_build_without_targetarch_names_buildkit() -> None:
    proc = _select("")
    assert proc.returncode != 0
    assert "BuildKit" in proc.stderr


def test_downloads_use_the_target_arch() -> None:
    assert "age-v${AGE_VERSION}-linux-${TARGETARCH}.tar.gz" in DOCKERFILE
    assert "rclone-v${RCLONE_VERSION}-linux-${TARGETARCH}.zip" in DOCKERFILE
    assert "amd64/" not in DOCKERFILE and "-linux-amd64" not in DOCKERFILE
