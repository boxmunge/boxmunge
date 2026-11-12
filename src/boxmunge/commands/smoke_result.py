# SPDX-License-Identifier: Apache-2.0
"""The smoke contract: the command run in the container, and what its exit
status and stderr mean.

Split from commands.check, which runs it in every container. Whether a
smoke could not be run or ran and failed is told by the exit status alone.
What the script writes on stderr is its message and never changes the
verdict: an app that exits 2 saying "cannot open database" is critical.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass


@dataclass
class SmokeResult:
    status: str  # "ok", "warning", "critical"
    message: str


# The statuses of a smoke that was never run. `docker exec` exits with them
# when it cannot start the command (126 cannot invoke it, 127 not found),
# and smoke_command with the same two when the script is not there to run.
# A script that exits with one itself is a warning either way.
CANNOT_RUN_STATUSES = (126, 127)

# `sh` exits 2, the app-critical status, on a script it cannot open (a
# severed bind mount, say), so the script is checked before sh is given it.
_SMOKE_COMMAND = r"""
s={script}
[ -f "$s" ] || {{ echo "smoke script $s is not in the container" >&2; exit 127; }}
[ -r "$s" ] || {{ echo "smoke script $s is not readable by the container's user" >&2; exit 126; }}
exec sh "$s" {service}
"""


def smoke_command(script: str, service: str) -> str:
    """The sh command that runs a service's smoke script in its container:
    ``sh <script> <service>``, or a CANNOT_RUN_STATUSES exit when the script
    is missing or unreadable (sh reads it, so it needs no execute bit)."""
    return _SMOKE_COMMAND.format(script=shlex.quote(script), service=shlex.quote(service))


def cannot_run(message: str) -> SmokeResult:
    """A smoke that could not be run says nothing about the app's health: a
    warning, so the operator hears of it, and never the critical that stops
    the project."""
    return SmokeResult(
        status="warning",
        message=f"smoke could not run (infrastructure, not app): {message}",
    )


def parse_smoke_stderr(stderr: str) -> str:
    """Parse smoke test stderr according to the boxmunge contract."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]

    if not lines:
        return "Smoke check failed (no detail provided)"
    if len(lines) == 1:
        return lines[0]
    return "Manual failure analysis required (smoke script produced multiple lines)"


def interpret_smoke_result(exit_code: int, stderr: str) -> SmokeResult:
    """Interpret a smoke run's exit status and stderr into a SmokeResult."""
    if exit_code == 0:
        return SmokeResult(status="ok", message="")
    message = parse_smoke_stderr(stderr)
    if exit_code in CANNOT_RUN_STATUSES:
        return cannot_run(message)
    if exit_code == 2:
        return SmokeResult(status="critical", message=message)
    return SmokeResult(status="warning", message=message)
