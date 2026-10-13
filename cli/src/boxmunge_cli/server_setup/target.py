# SPDX-License-Identifier: Apache-2.0
"""Parse server-setup target: [user@]host."""

from __future__ import annotations

from boxmunge_cli.server_setup.validate import is_ip_address, login_user, ssh_host

__all__ = ["is_ip_address", "parse_target"]


def parse_target(target: str) -> tuple[str, str]:
    """Parse [user@]host into (user, host). Default user is root.

    Raises ValueError for an invalid user or host.
    """
    user, host = target.split("@", 1) if "@" in target else ("root", target)
    return login_user(user), ssh_host(host)
