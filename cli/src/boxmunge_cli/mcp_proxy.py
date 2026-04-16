# SPDX-License-Identifier: Apache-2.0
"""MCP stdio proxy — transparent tunnel to boxmunge-server via SSH."""

from __future__ import annotations

import signal
import subprocess
import sys
from typing import Any

from boxmunge_cli.ssh import build_ssh_cmd


def run_mcp_proxy(config: dict[str, Any]) -> int:
    """Run the MCP proxy. Blocks until the SSH process exits."""
    cmd = build_ssh_cmd(config, "mcp-serve")
    proc = subprocess.Popen(cmd)

    def _terminate(signum: int, frame: Any) -> None:
        proc.terminate()

    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGINT, _terminate)

    return proc.wait()
