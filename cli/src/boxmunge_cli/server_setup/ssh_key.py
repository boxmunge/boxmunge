# SPDX-License-Identifier: Apache-2.0
"""The SSH public key server-setup authorises for the deploy and supervisor users.

Accepts exactly one OpenSSH public-key line, from --ssh-key (a file or the
key itself), the SSH agent, or ~/.ssh/*.pub. A private key is refused
outright: it would travel in the install command and land in
authorized_keys.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path


class SSHKeyError(Exception):
    """Raised when no usable SSH public key can be found."""


# Most preferred first, when choosing among several keys.
KEY_TYPES = (
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa",
)

_KEY_FILES = (
    ".ssh/id_ed25519.pub",
    ".ssh/id_ed25519_sk.pub",
    ".ssh/id_ecdsa.pub",
    ".ssh/id_ecdsa_sk.pub",
    ".ssh/id_rsa.pub",
)


def fingerprint(key_b64: str) -> str:
    """OpenSSH SHA256 fingerprint of base64 key material. Raises ValueError."""
    try:
        blob = base64.b64decode(key_b64, validate=True)
    except binascii.Error as e:
        raise ValueError(f"key material is not valid base64: {e}") from e
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


@dataclass(frozen=True)
class PublicKey:
    key_type: str
    key_b64: str
    comment: str

    @property
    def line(self) -> str:
        return " ".join(p for p in (self.key_type, self.key_b64, self.comment) if p)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.key_b64)

    def describe(self) -> str:
        comment = f" ({self.comment})" if self.comment else ""
        return f"{self.key_type} {self.fingerprint}{comment}"


def parse_public_key(text: str, source: str) -> PublicKey:
    """Parse exactly one public-key line. Raises SSHKeyError naming source."""
    if "PRIVATE KEY" in text:
        raise SSHKeyError(
            f"{source} is a PRIVATE key. Never send a private key anywhere: "
            "pass the public key (the .pub file) instead."
        )
    lines = [ln.strip() for ln in text.splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    if len(lines) != 1:
        raise SSHKeyError(f"{source} must hold exactly one public key line; "
                          f"found {len(lines)}.")
    parts = lines[0].split(None, 2)
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise SSHKeyError(f"{source} is not an OpenSSH public key (expected one of: "
                          f"{', '.join(KEY_TYPES)}).")
    key_type, key_b64 = parts[0], parts[1]
    try:
        blob = base64.b64decode(key_b64, validate=True)
        (n,) = struct.unpack(">I", blob[:4])
        embedded = blob[4:4 + n].decode("ascii")
    except (binascii.Error, struct.error, UnicodeDecodeError) as e:
        raise SSHKeyError(f"{source}: malformed key material ({e}).") from e
    if embedded != key_type:
        raise SSHKeyError(f"{source}: key says {key_type} but its material is {embedded}.")
    comment = parts[2] if len(parts) == 3 else ""
    if any(ord(c) < 0x20 for c in comment):
        raise SSHKeyError(f"{source}: the key comment contains control characters.")
    return PublicKey(key_type, key_b64, comment)


def detect_ssh_key(explicit: str | None) -> PublicKey:
    """--ssh-key (file or inline key), else the SSH agent, else ~/.ssh/*.pub."""
    if explicit is not None:
        if explicit.split(None, 1)[0] in KEY_TYPES:
            return parse_public_key(explicit, "--ssh-key")
        path = Path(explicit).expanduser()
        if path.is_file():
            return parse_public_key(path.read_text(errors="replace"), str(path))
        raise SSHKeyError(f"SSH key file not found: {explicit}")

    key = _from_agent() or _from_files()
    if key is None:
        raise SSHKeyError(
            "No SSH public key found. Provide one with --ssh-key "
            "or add a key to your SSH agent."
        )
    return key


def _preferred(keys: list[PublicKey]) -> PublicKey | None:
    ranked = sorted(keys, key=lambda k: KEY_TYPES.index(k.key_type))
    return ranked[0] if ranked else None


def _from_agent() -> PublicKey | None:
    """Try the SSH agent, preferring ed25519. Unparseable agent lines are skipped."""
    result = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None
    keys = []
    for line in result.stdout.splitlines():
        try:
            keys.append(parse_public_key(line, "ssh-agent key"))
        except SSHKeyError:
            continue  # e.g. certificates; the agent may hold several kinds
    return _preferred(keys)


def _from_files() -> PublicKey | None:
    home = Path.home()
    for rel in _KEY_FILES:
        path = home / rel
        if path.is_file():
            return parse_public_key(path.read_text(errors="replace"), str(path))
    return None
