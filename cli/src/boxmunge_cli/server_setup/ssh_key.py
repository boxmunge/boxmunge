# SPDX-License-Identifier: Apache-2.0
"""SSH public key auto-detection for server-setup."""

from __future__ import annotations

import subprocess
from pathlib import Path


class SSHKeyError(Exception):
    """Raised when no SSH public key can be found."""


_KEY_PREFERENCE = ["ssh-ed25519", "ssh-ecdsa", "ssh-rsa"]

_KEY_FILES = [
    ".ssh/id_ed25519.pub",
    ".ssh/id_rsa.pub",
    ".ssh/id_ecdsa.pub",
]


def detect_ssh_key(explicit: str | None) -> str:
    """Detect or read an SSH public key.

    If explicit is a file path, read it. If it starts with 'ssh-', return it.
    Otherwise, try the SSH agent, then fall back to key files.
    Raises SSHKeyError if no key is found.
    """
    if explicit is not None:
        if explicit.startswith("ssh-"):
            return explicit.strip()
        path = Path(explicit)
        if path.is_file():
            return path.read_text().strip()
        raise SSHKeyError(f"SSH key file not found: {explicit}")

    key = _from_agent()
    if key:
        return key

    key = _from_files()
    if key:
        return key

    raise SSHKeyError(
        "No SSH public key found. Provide one with --ssh-key "
        "or add a key to your SSH agent."
    )


def _from_agent() -> str | None:
    """Try to get a key from the SSH agent, preferring ed25519."""
    result = subprocess.run(
        ["ssh-add", "-L"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None

    keys = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    for pref in _KEY_PREFERENCE:
        for key in keys:
            if key.startswith(pref):
                return key
    return keys[0] if keys else None


def _from_files() -> str | None:
    """Try to read a key from well-known file locations."""
    home = Path.home()
    for rel in _KEY_FILES:
        path = home / rel
        if path.is_file():
            return path.read_text().strip()
    return None
