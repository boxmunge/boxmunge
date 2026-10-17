# SPDX-License-Identifier: Apache-2.0
"""Health check: is boxmunge's sshd drop-in installed as this release ships it?

install.sh (bootstrap/sshd-hardening.sh) installs the package's
sshd/00-boxmunge.conf as /etc/ssh/sshd_config.d/00-boxmunge.conf and proves
sshd enforces it. Without it a cloud image's drop-in turns password logins
back on, and deploy's key could forward the Docker socket past the
restricted shell, so a missing or changed file is an error.

The file alone does not say what sshd does with it: AcceptEnv values add up
across Match blocks, so a later drop-in can widen what deploy accepts. The
second check asks sshd (`sshd -T`, root only) for deploy's effective
environment settings.
"""
from __future__ import annotations

import os
import subprocess
from importlib.resources import files
from pathlib import Path

from boxmunge.commands.health_cmd import HealthCheck

NAME = "sshd-hardening"
ENV_NAME = "sshd-deploy-env"
SSHD = "/usr/sbin/sshd"
# What `sshd -T` must report for deploy, as bootstrap/sshd-hardening.sh checks.
DEPLOY_ACCEPTENV = ("COLORTERM", "LANG", "LC_*", "NO_COLOR")
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


def check_sshd_deploy_env(run=subprocess.run) -> HealthCheck:
    if os.geteuid() != 0:
        return HealthCheck(ENV_NAME, "skip",
                           "needs root to ask sshd (run `sudo boxmunge-server health`)")
    result = run([SSHD, "-T", "-C", "user=deploy,host=localhost,addr=127.0.0.1"],
                 capture_output=True, text=True, check=False, timeout=30)
    if result.returncode != 0:
        return HealthCheck(ENV_NAME, "error",
                           f"sshd -T failed ({result.stderr.strip()}): {_FIX}")
    lines = result.stdout.splitlines()
    accepted = sorted(line.split(" ", 1)[1] for line in lines if line.startswith("acceptenv "))
    problems = []
    if tuple(accepted) != DEPLOY_ACCEPTENV:
        problems.append(f"deploy accepts {', '.join(accepted) or 'nothing'} from clients, "
                        f"not exactly {', '.join(DEPLOY_ACCEPTENV)}")
    if "permituserenvironment no" not in lines:
        problems.append("PermitUserEnvironment is not no")
    if problems:
        return HealthCheck(ENV_NAME, "error",
                           "; ".join(problems) + ". Remove the sshd setting that widens it "
                           "(`sudo sshd -T -C user=deploy,host=localhost,addr=127.0.0.1` "
                           "shows the result) and reload sshd; install.sh refuses such a "
                           "box, so this changed after install")
    return HealthCheck(ENV_NAME, "ok", "deploy accepts only LANG, LC_*, COLORTERM, NO_COLOR")
