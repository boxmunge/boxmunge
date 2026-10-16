# SPDX-License-Identifier: Apache-2.0
"""ssh/scp argv for the server being set up. Host keys are always verified."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, replace
from pathlib import Path

from boxmunge_cli.ssh import scp_host


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

    def ssh(self, argv: list[str], sudo: bool = False) -> list[str]:
        """ssh argv that runs argv on the server, every element quoted.

        ssh sends the remote command as one string that the login shell
        parses, so it is built with shlex.join: no value can break out of
        its argument, whatever it contains.
        """
        remote = ["sudo", "-n", *argv] if sudo else argv
        return ["ssh", "-p", str(self.port), *self.options(), "--",
                f"{self.user}@{self.host}", shlex.join(remote)]

    def scp(self, local: str, remote_path: str) -> list[str]:
        return ["scp", "-P", str(self.port), *self.options(), "--",
                local, f"{self.user}@{scp_host(self.host)}:{remote_path}"]

    def at_port(self, port: int) -> Target:
        return replace(self, port=port)

