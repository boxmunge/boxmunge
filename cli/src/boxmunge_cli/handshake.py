# SPDX-License-Identifier: Apache-2.0
"""Client/server compatibility handshake.

The client and server version independently (client 0.x on PyPI, server
releases on GitHub), so their versions are never compared with each other.
Instead:
  - the server says the oldest client it accepts (min_client_version);
  - the client says the oldest server it needs (MIN_SERVER_VERSION);
  - the server says the newest manifest schema it understands, and a
    manifest declaring a newer one is refused before upload.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

from boxmunge_cli import __version__
from boxmunge_cli.exitcodes import CONNECTION, INCOMPATIBLE, SSH_CONNECTION_FAILED
from boxmunge_cli.ssh import build_ssh_cmd
from boxmunge_cli.version import parse_version

# Oldest boxmunge-server this client works with: the release whose command
# surface (stage/prod-deploy/promote flags, status --json, logs options,
# handshake schema_version) the client was built and tested against. The one
# exception is prod-deploy --abandon, which is newer: older servers reject it
# with "unknown argument", and it is not worth refusing every command for.
MIN_SERVER_VERSION = "0.10.0"


class HandshakeError(Exception):
    """Raised when the server handshake fails or versions are incompatible."""

    def __init__(self, message: str, exit_code: int = INCOMPATIBLE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class ServerInfo:
    server_version: str
    min_client_version: str
    schema_version: int


def _version(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    try:
        parse_version(value)
    except ValueError as e:
        raise HandshakeError(f"Invalid handshake response: '{field}' {e}.") from e
    return value  # type: ignore[return-value]


def _parse_response(stdout: str) -> ServerInfo:
    try:
        data = json.loads(stdout)
    except ValueError:
        raise HandshakeError(
            "Malformed handshake response from server (not JSON). "
            "Is the server running a compatible version of boxmunge-server?"
        )
    if not isinstance(data, dict):
        raise HandshakeError("Invalid handshake response: expected a JSON object.")
    schema = data.get("schema_version")
    if isinstance(schema, bool) or not isinstance(schema, int) or schema < 1:
        raise HandshakeError(
            f"Invalid handshake response: 'schema_version' must be a positive "
            f"integer, got {schema!r}.")
    return ServerInfo(_version(data, "server_version"),
                      _version(data, "min_client_version"), schema)


def check_server_compatibility(config: dict[str, Any],
                               manifest_schema: int | None = None,
                               batch: bool = False) -> ServerInfo:
    """Run the server's handshake and refuse incompatible combinations.

    manifest_schema: the schema_version of the manifest about to be
    uploaded, checked against what the server understands. batch: never
    prompt (no person at a terminal).
    """
    result = subprocess.run(build_ssh_cmd(config, "handshake", batch=batch),
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or f"ssh exited with {result.returncode}"
        raise HandshakeError(
            f"Handshake with {config['user']}@{config['server']}:{config['port']} "
            f"failed: {detail}",
            CONNECTION if result.returncode == SSH_CONNECTION_FAILED else INCOMPATIBLE,
        )
    info = _parse_response(result.stdout)

    if parse_version(__version__) < parse_version(info.min_client_version):
        raise HandshakeError(
            f"This boxmunge CLI ({__version__}) is too old for the server, which "
            f"requires >= {info.min_client_version}. "
            "Upgrade: pip install --upgrade boxmunge"
        )
    if parse_version(info.server_version) < parse_version(MIN_SERVER_VERSION):
        raise HandshakeError(
            f"The server runs boxmunge-server {info.server_version}; this CLI needs "
            f">= {MIN_SERVER_VERSION}. Upgrade the server (run 'upgrade' on it), "
            "or install an older CLI."
        )
    if manifest_schema is not None and manifest_schema > info.schema_version:
        raise HandshakeError(
            f"manifest.yml declares schema_version {manifest_schema}, but the server "
            f"understands up to {info.schema_version}. Upgrade the server, or use "
            f"schema_version {info.schema_version}."
        )
    return info
