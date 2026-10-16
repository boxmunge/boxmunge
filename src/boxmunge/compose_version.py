# SPDX-License-Identifier: Apache-2.0
"""The minimum Docker Compose version boxmunge supports, and its check.

Secrets reach containers as single-quoted values in Compose env files, with
``\\'`` for a quote. Compose reads that literally from 2.24 on; 2.20-2.23
pass the backslash through and older releases fail to parse the file.
install.sh refuses to install or upgrade below this version (keep its
MIN_COMPOSE_VERSION in step), and `doctor` reports it.
"""
from __future__ import annotations

import re
import subprocess

MIN_COMPOSE_VERSION = (2, 24, 0)
_VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def compose_version_problem() -> str | None:
    """Why the installed Compose is unusable, or None if it is supported."""
    want = ".".join(map(str, MIN_COMPOSE_VERSION))
    try:
        result = subprocess.run(["docker", "compose", "version", "--short"],
                                capture_output=True, text=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"cannot run 'docker compose version': {e}"
    out = result.stdout.strip()
    match = _VERSION_RE.match(out)
    if result.returncode != 0 or match is None:
        return (f"'docker compose version --short' gave {out!r} "
                f"(exit {result.returncode}): {result.stderr.strip()}")
    found = tuple(int(g) for g in match.groups())
    if found < MIN_COMPOSE_VERSION:
        return (f"Docker Compose {out} is older than {want}, which boxmunge needs to "
                "pass secrets to containers unchanged. Upgrade it: "
                "apt-get install --only-upgrade docker-compose-plugin")
    return None
