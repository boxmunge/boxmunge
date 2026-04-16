# SPDX-License-Identifier: Apache-2.0
"""handshake — return server version info for client compatibility checks."""

import json

from boxmunge.manifest import CURRENT_SCHEMA_VERSION
from boxmunge.version import get_build_version, parse_version_string

# Minimum client version this server will accept.
# Bump this when a server change would break older clients.
MIN_CLIENT_VERSION = "0.1.0"


def run_handshake() -> dict:
    """Build and return the handshake payload."""
    full_version = get_build_version()
    semver, _ = parse_version_string(full_version)
    return {
        "server_version": semver,
        "min_client_version": MIN_CLIENT_VERSION,
        "schema_version": CURRENT_SCHEMA_VERSION,
    }


def cmd_handshake(args: list[str]) -> None:
    """Print handshake JSON to stdout."""
    print(json.dumps(run_handshake()))
