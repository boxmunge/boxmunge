# SPDX-License-Identifier: Apache-2.0
"""Client-side version handshake with boxmunge-server."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from boxmunge_cli import __version__
from boxmunge_cli.ssh import build_ssh_cmd


class HandshakeError(Exception):
    """Raised when the server handshake fails or versions are incompatible."""


def _parse_version(version: str) -> tuple[int, ...]:
    """Parse a semver string into a comparable tuple."""
    parts = version.split("+")[0]
    return tuple(int(x) for x in parts.split("."))


def check_server_compatibility(config: dict[str, Any]) -> None:
    """Call server handshake and verify version compatibility.

    Raises HandshakeError if the client is too old.
    Prints a warning to stderr if the server is old.
    """
    cmd = build_ssh_cmd(config, "handshake")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode != 0:
        raise HandshakeError(
            f"Handshake failed: could not connect to "
            f"{config['server']}:{config['port']} (exit code {result.returncode})."
        )

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        raise HandshakeError(
            "Malformed handshake response from server. "
            "Is the server running a compatible version of boxmunge-server?"
        )

    for field in ("server_version", "min_client_version", "schema_version"):
        if field not in data:
            raise HandshakeError(f"Invalid handshake response: missing '{field}'.")

    min_client = _parse_version(data["min_client_version"])
    client_version = _parse_version(__version__)

    if client_version < min_client:
        raise HandshakeError(
            f"This boxmunge CLI (v{__version__}) is too old for the server "
            f"(requires >= {data['min_client_version']}). "
            f"Please upgrade: pip install --upgrade boxmunge"
        )

    server_version = _parse_version(data["server_version"])
    if server_version < client_version:
        print(
            f"WARNING: Server is running an old version "
            f"(v{data['server_version']}). Some features may not work.",
            file=sys.stderr,
        )
