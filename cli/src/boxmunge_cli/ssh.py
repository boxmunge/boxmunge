# SPDX-License-Identifier: Apache-2.0
"""SSH and SCP command building and execution.

Commands run locally with shell=False. ssh sends the remote command to the
server as one string that the server parses again, so the command and its
arguments are joined with shlex.join: an argument with spaces or quotes
reaches the server as one argument. The deploy user's restricted shell then
splits it with shlex and runs only allowlisted commands.
"""

from __future__ import annotations

import shlex
import subprocess
from typing import Any

from boxmunge_cli.exitcodes import CONNECTION, SSH_CONNECTION_FAILED


def build_ssh_cmd(config: dict[str, Any], command: str, *args: str,
                  batch: bool = False) -> list[str]:
    """Build an SSH command list from config and arguments.

    batch: never prompt (for callers with no person at a terminal).
    """
    return [
        "ssh",
        "-p", str(config["port"]),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=15",
        *(["-o", "BatchMode=yes"] if batch else []),
        f"{config['user']}@{config['server']}",
        shlex.join([command, *args]),
    ]


def _scp_host(server: str) -> str:
    """scp needs an IPv6 address in brackets (ssh does not)."""
    return f"[{server}]" if ":" in server else server


def build_scp_cmd(config: dict[str, Any], local_path: str) -> list[str]:
    """Build an SCP upload command list."""
    return [
        "scp",
        "-P", str(config["port"]),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=15",
        local_path,
        f"{config['user']}@{_scp_host(config['server'])}:",
    ]


def _exit_code(returncode: int) -> int:
    """ssh's own failure (255) becomes CONNECTION; anything else is the remote's."""
    return CONNECTION if returncode == SSH_CONNECTION_FAILED else returncode


def run_ssh(config: dict[str, Any], command: str, *args: str) -> int:
    """Execute an SSH command. Returns the remote exit code (4 if ssh failed)."""
    result = subprocess.run(build_ssh_cmd(config, command, *args), check=False)
    return _exit_code(result.returncode)


def run_scp(config: dict[str, Any], local_path: str) -> int:
    """Upload a file via SCP. Returns the exit code."""
    result = subprocess.run(build_scp_cmd(config, local_path), check=False)
    return _exit_code(result.returncode)
