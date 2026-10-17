# SPDX-License-Identifier: Apache-2.0
"""Health check: is boxmunge's sshd drop-in installed as this release ships it?

install.sh (bootstrap/sshd-hardening.sh) installs the package's
sshd/00-boxmunge.conf as /etc/ssh/sshd_config.d/00-boxmunge.conf and proves
sshd enforces it. Without it a cloud image's drop-in turns password logins
back on, and deploy's key could forward the Docker socket past the
restricted shell, so a missing or changed file is an error.
"""
from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from boxmunge.commands.health_cmd import HealthCheck

NAME = "sshd-hardening"
INSTALLED = Path("/etc/ssh/sshd_config.d/00-boxmunge.conf")
_FIX = ("re-run the installer as root (`sudo bash boxmunge-install.sh`, from this "
        "version's GitHub release); it rewrites the file and checks sshd enforces it")


def shipped_dropin() -> str:
    return files("boxmunge").joinpath("sshd/00-boxmunge.conf").read_text()


def check_sshd_hardening(installed: Path = INSTALLED) -> HealthCheck:
    try:
        text = installed.read_text()
    except FileNotFoundError:
        return HealthCheck(NAME, "error", f"{installed} is missing: {_FIX}")
    except (OSError, UnicodeDecodeError) as e:
        return HealthCheck(NAME, "error", f"cannot read {installed} ({e}): {_FIX}")
    if text != shipped_dropin():
        return HealthCheck(NAME, "error",
                           f"{installed} differs from the copy this release ships: {_FIX}")
    return HealthCheck(NAME, "ok", f"{installed} as shipped")
