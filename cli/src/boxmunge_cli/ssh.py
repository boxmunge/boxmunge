# SPDX-License-Identifier: Apache-2.0
"""SSH and SCP command building and execution.

All commands are built as explicit lists and executed with shell=False
to prevent injection from untrusted .boxmunge config values.
"""

from __future__ import annotations

import subprocess
from typing import Any


def build_ssh_cmd(config: dict[str, Any], command: str, *args: str) -> list[str]:
    """Build an SSH command list from config and arguments."""
    cmd = [
        "ssh",
        "-p", str(config["port"]),
        "-o", "StrictHostKeyChecking=accept-new",
        f"{config['user']}@{config['server']}",
        command,
    ]
    cmd.extend(args)
    return cmd


def build_scp_cmd(config: dict[str, Any], local_path: str) -> list[str]:
    """Build an SCP upload command list."""
    return [
        "scp",
        "-O",  # legacy SCP protocol (not SFTP)
        "-P", str(config["port"]),
        "-o", "StrictHostKeyChecking=accept-new",
        local_path,
        f"{config['user']}@{config['server']}:",
    ]


def run_ssh(config: dict[str, Any], command: str, *args: str) -> int:
    """Execute an SSH command. Returns the exit code."""
    cmd = build_ssh_cmd(config, command, *args)
    result = subprocess.run(cmd, check=False)
    return result.returncode


def run_scp(config: dict[str, Any], local_path: str) -> int:
    """Upload a file via SCP. Returns the exit code."""
    cmd = build_scp_cmd(config, local_path)
    result = subprocess.run(cmd, check=False)
    return result.returncode
