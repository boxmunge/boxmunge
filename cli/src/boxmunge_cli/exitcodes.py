# SPDX-License-Identifier: Apache-2.0
"""Exit codes, the same for every command.

  0  success
  1  failure (bundle refused, upload failed, the server command failed, ...)
  2  usage error (unknown option, missing argument)
  3  client and server are incompatible (see the handshake message)
  4  the server could not be reached (ssh failed to connect or authenticate)

Commands that run a server command exit with that command's own code, except
that ssh's connection failure (255) is reported as 4.
"""

from __future__ import annotations

OK = 0
FAILURE = 1
USAGE = 2
INCOMPATIBLE = 3
CONNECTION = 4

SSH_CONNECTION_FAILED = 255


class CliExit(Exception):
    """Stop the command with an exit code; main() prints the message as ERROR."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
