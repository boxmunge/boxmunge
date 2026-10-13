# SPDX-License-Identifier: Apache-2.0
"""ssh/scp argv for the server being set up. Host keys are always verified."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path


def default_known_hosts() -> Path:
    return Path.home() / ".ssh" / "known_hosts"


@dataclass(frozen=True)
class Target:
    user: str
    host: str
    port: int
    known_hosts: Path

    def options(self) -> list[str]:
        return ["-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={self.known_hosts}",
                "-o", "ConnectTimeout=15"]

    def ssh(self, command: str, sudo: bool = False) -> list[str]:
        remote = f"sudo bash -c {_shell_quote(command)}" if sudo else command
        return ["ssh", "-p", str(self.port), *self.options(),
                f"{self.user}@{self.host}", remote]

    def scp(self, local: str, remote_path: str) -> list[str]:
        return ["scp", "-P", str(self.port), *self.options(),
                local, f"{self.user}@{self.host}:{remote_path}"]

    def at_port(self, port: int) -> Target:
        return replace(self, port=port)


def _shell_quote(s: str) -> str:
    """Quote a string for embedding in a shell command using $'...' syntax."""
    escaped = s.replace("\\", "\\\\").replace("'", "\\'")
    return f"$'{escaped}'"
