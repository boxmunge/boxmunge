# SPDX-License-Identifier: Apache-2.0
"""The minimum Docker Compose version boxmunge supports, and its check.

boxmunge resolves user compose with ``config --no-env-resolution``, which
Compose accepts from 2.35.0 (2.34 and older reject the flag, so validation
could not run). That also covers secrets' single-quoted env-file values with
``\\'`` for a quote, which Compose reads literally from 2.24 on.
install.sh refuses to install or upgrade below this version (keep its
MIN_COMPOSE_VERSION in step), and `doctor` reports it.
"""
from __future__ import annotations

import re
import subprocess

from boxmunge.docker_run import docker_env

MIN_COMPOSE_VERSION = (2, 35, 0)
# Same rule as install.sh's require_compose_version: trim ASCII whitespace,
# then the whole output must be one version, optionally with a packaging
# suffix (-desktop.1, +ds1-0ubuntu1~24.04.1). Anything else is unreadable,
# never guessed at.
_WHITESPACE = " \t\r\n\v\f"
_VERSION_RE = re.compile(r"v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][^ \t\r\n\v\f]*)?")
_UPGRADE = "apt-get install --only-upgrade docker-compose-plugin"


def compose_version_problem() -> str | None:
    """Why the installed Compose is unusable, or None if it is supported."""
    want = ".".join(map(str, MIN_COMPOSE_VERSION))
    try:
        result = subprocess.run(["docker", "compose", "version", "--short"],
                                capture_output=True, check=False, timeout=30,
                                env=docker_env())
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"cannot run 'docker compose version --short': {e}"
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        return (f"'docker compose version --short' failed (exit {result.returncode}): "
                f"{stderr}. Install docker-compose-plugin {want} or newer.")
    # Bytes, not text mode: text mode would turn CRs into newlines.
    raw = result.stdout.decode("utf-8", "replace")
    match = _VERSION_RE.fullmatch(raw.strip(_WHITESPACE))
    if match is None:
        return (f"could not read the Docker Compose version from "
                f"'docker compose version --short', which printed {raw!r}")
    found = tuple(int(g) for g in match.groups()[:3])
    if found < MIN_COMPOSE_VERSION:
        return (f"Docker Compose {match.group(0)} is older than {want}, which "
                f"boxmunge needs to pass secrets to containers unchanged. "
                f"Upgrade it: {_UPGRADE}")
    return None
