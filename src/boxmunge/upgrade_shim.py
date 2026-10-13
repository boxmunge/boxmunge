# SPDX-License-Identifier: Apache-2.0
"""How unprivileged callers reach the root upgrade shim.

The deploy shell and the MCP server both run as deploy. A platform upgrade
needs root (venv swap, stash of root-owned config, probation), so both go
through the same sudo rule, which permits exactly these two invocations.
See install-sudoers in scripts/boxmunge-upgrade.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def shim_command(paths: BoxPaths, target: str | None = None) -> list[str]:
    """argv for `upgrade` (discover the latest) or `upgrade --target <version>`.

    The shim validates the version and refuses downgrades and blocklisted
    versions; this only builds the command line.
    """
    shim = str(paths.bin / "boxmunge-upgrade")
    if target is None:
        return ["sudo", "-n", shim, "auto"]
    return ["sudo", "-n", shim, "target", target]
