# SPDX-License-Identifier: Apache-2.0
"""Verify the server's SSH host key before server-setup sends it anything.

A host already in known_hosts is checked by ssh itself (StrictHostKeyChecking
=yes). For a new host, the key offered by the server must match a
--host-key-fingerprint given on the command line, or be confirmed by a person
at a terminal after seeing its fingerprint. Only the key that was verified is
recorded. Without either, server-setup stops: it never trusts on first use
silently.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Callable

from boxmunge_cli.server_setup.remote import Target
from boxmunge_cli.server_setup.ssh_key import fingerprint as key_fingerprint

# Preference order when a person is asked to confirm one key.
_PREFERRED = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
              "ecdsa-sha2-nistp521", "rsa-sha2-512", "ssh-rsa")

Confirm = Callable[[str], bool]


class HostKeyError(Exception):
    """Raised when the server's host key cannot be verified."""


def host_pattern(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def fingerprint(key_b64: str) -> str:
    try:
        return key_fingerprint(key_b64)
    except ValueError as e:
        raise HostKeyError(f"Malformed host key from ssh-keyscan: {e}") from e


def _lookup(target: Target, port: int) -> list[tuple[str, str]]:
    """Known (type, key) pairs for host:port in target.known_hosts."""
    if not target.known_hosts.is_file():
        return []
    result = subprocess.run(
        ["ssh-keygen", "-F", host_pattern(target.host, port), "-f", str(target.known_hosts)],
        capture_output=True, text=True, check=False,
    )
    keys = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if line.startswith("#") or len(parts) < 3 or parts[0].startswith("@"):
            continue
        keys.append((parts[1], parts[2]))
    return keys


# Only the types server-setup can record. Asking for the sk-* types too makes
# ssh-keyscan open more unauthenticated connections, each of which sshd's
# PerSourcePenalties (OpenSSH >= 9.8, on by default in Debian 13) counts
# against this address.
_SCAN_TYPES = "ed25519,ecdsa,rsa"


def _scan(target: Target) -> list[tuple[str, str]]:
    result = subprocess.run(
        ["ssh-keyscan", "-T", "15", "-t", _SCAN_TYPES, "-p", str(target.port), target.host],
        capture_output=True, text=True, check=False,
    )
    keys = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if line.startswith("#") or len(parts) < 3:
            continue
        keys.append((parts[1], parts[2]))
    if not keys:
        stderr = result.stderr.strip() or "(nothing)"
        raise HostKeyError(
            f"Could not read the SSH host key of {target.host}:{target.port}: "
            f"ssh-keyscan returned no keys (exit {result.returncode}).\n"
            f"ssh-keyscan said: {stderr}\n"
            "If sshd is reachable, it may be rate-limiting this address: OpenSSH "
            "9.8 and later (PerSourcePenalties, on by default in Debian 13) "
            "refuses an address for a while after unauthenticated connections "
            "such as ssh-keyscan's. Wait a few minutes and retry (with "
            "--host-key-fingerprint SHA256:... so the retry needs no prompt), or "
            "skip the scan: add the server's /etc/ssh/ssh_host_ed25519_key.pub "
            f"(from its console) to {target.known_hosts} as "
            f"'{host_pattern(target.host, target.port)} ssh-ed25519 AAAA...'."
        )
    return keys


def _append(known_hosts: Path, pattern: str, keys: list[tuple[str, str]]) -> None:
    known_hosts.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(known_hosts, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as f:
        for key_type, key in keys:
            f.write(f"{pattern} {key_type} {key}\n")


def _rank(key_type: str) -> int:
    return _PREFERRED.index(key_type) if key_type in _PREFERRED else len(_PREFERRED)


def ensure_trusted(target: Target, expected: str | None, confirm: Confirm | None) -> None:
    """Make sure target's host key is verified and recorded in known_hosts.

    confirm is None when nobody can be asked (non-interactive or --yes).
    """
    if _lookup(target, target.port):
        print(f"Host key for {target.host}:{target.port} is already in "
              f"{target.known_hosts}; ssh will verify it.")
        return
    offered = _scan(target)
    if expected is not None:
        trusted = [k for k in offered if fingerprint(k[1]) == expected]
        if not trusted:
            seen = ", ".join(f"{t} {fingerprint(k)}" for t, k in offered)
            raise HostKeyError(
                f"The host key offered by {target.host}:{target.port} does not match "
                f"--host-key-fingerprint {expected}. Offered: {seen}. Do not continue "
                "until you know why: this is what a man-in-the-middle looks like."
            )
    elif confirm is not None:
        key_type, key = sorted(offered, key=lambda k: _rank(k[0]))[0]
        print(f"The server {target.host}:{target.port} is not in {target.known_hosts}.")
        print(f"  {key_type} key fingerprint: {fingerprint(key)}")
        print("Compare it with the fingerprint your VPS provider shows, or with\n"
              "  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub\n"
              "run on the server's console.")
        if not confirm("Trust this host key? [y/N] "):
            raise HostKeyError("Host key not trusted; nothing was changed on the server.")
        trusted = [(key_type, key)]
    else:
        raise HostKeyError(
            f"{target.host}:{target.port} is not in {target.known_hosts} and its host key "
            "cannot be confirmed non-interactively. Pass --host-key-fingerprint "
            "SHA256:... (from your VPS provider, or 'ssh-keygen -lf "
            "/etc/ssh/ssh_host_ed25519_key.pub' on the server's console)."
        )
    _append(target.known_hosts, host_pattern(target.host, target.port), trusted)


def record_for_port(target: Target, new_port: int) -> None:
    """After setup moves sshd to new_port, trust the same verified key there."""
    if new_port == target.port or _lookup(target, new_port):
        return
    keys = _lookup(target, target.port)
    if not keys:
        raise HostKeyError(f"No verified host key for {target.host}:{target.port} to copy.")
    _append(target.known_hosts, host_pattern(target.host, new_port), keys)
