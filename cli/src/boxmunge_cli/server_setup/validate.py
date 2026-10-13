# SPDX-License-Identifier: Apache-2.0
"""Up-front validation of the values server-setup sends to the server.

Quoting keeps these values from breaking out of their arguments; validation
keeps nonsense out of the server's config (Caddy, Let's Encrypt, sshd), which
receives them verbatim.
"""

from __future__ import annotations

import ipaddress
import re

_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
# A public name, as the server's own host rule (src/boxmunge/manifest.py
# _HOST_LABEL_RE) accepts it, and the looser RFC 1123 form for test setups.
_DNS_NAME = re.compile(rf"({_LABEL}\.)+[a-z]{{2,}}")
_RFC1123_NAME = re.compile(rf"{_LABEL}(\.{_LABEL})*")
_EMAIL = re.compile(
    r"[A-Za-z0-9._%+-]+@([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
)
_LOGIN_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


def dns_hostname(value: str, public: bool = True) -> str:
    """The server's hostname. public: a name Let's Encrypt can issue for."""
    pattern = _DNS_NAME if public else _RFC1123_NAME
    if not pattern.fullmatch(value) or len(value) > 253:
        kind = "public DNS name" if public else "hostname"
        raise ValueError(f"invalid hostname {value!r}: expected a lowercase {kind} "
                         "such as box.example.com")
    return value


def email(value: str) -> str:
    if not _EMAIL.fullmatch(value):
        raise ValueError(f"invalid email {value!r}: expected name@example.com")
    return value


def login_user(value: str) -> str:
    if not _LOGIN_USER.fullmatch(value):
        raise ValueError(f"invalid user {value!r}: expected a POSIX user name")
    return value


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def ssh_host(value: str) -> str:
    """A host to connect to: an IP address or a DNS name (any case)."""
    if is_ip_address(value):
        return value
    if _RFC1123_NAME.fullmatch(value.lower()) and len(value) <= 253:
        return value
    raise ValueError(f"invalid host {value!r}: expected a hostname or IP address")
