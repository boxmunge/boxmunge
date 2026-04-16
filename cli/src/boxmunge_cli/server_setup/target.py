# SPDX-License-Identifier: Apache-2.0
"""Parse server-setup target: [user@]host with IP detection."""

from __future__ import annotations

import re

_IPV4 = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def parse_target(target: str) -> tuple[str, str]:
    """Parse [user@]host into (user, host). Default user is root."""
    if "@" in target:
        user, host = target.split("@", 1)
        return user, host
    return "root", target


def is_ip_address(host: str) -> bool:
    """Check if host looks like an IP address rather than a hostname."""
    if _IPV4.match(host):
        return True
    if ":" in host:
        return True
    return False
