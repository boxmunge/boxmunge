# SPDX-License-Identifier: Apache-2.0
"""The smoke contract: the command run in the container, and what its
output and exit status mean.

Split from commands.check, which runs it in every container. Whether a
smoke could not be run, or ran and failed, is told by whether the script
was started: the command says so on stdout once the script is there to run
and before it is given control, so only a script that ran has a verdict.
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


# The first line of stdout of a smoke whose script was started. The script's
# own output comes after it, so nothing the script prints can take it away,
# and nothing but the command below prints it first.
STARTED = "boxmunge-smoke-started"

# A shell's statuses for a command that cannot be invoked (126) or is not
# found (127). `docker exec` and the command below exit with them for a
# smoke that was never started; from a script that ran, they are its own.
COMMAND_NOT_RUN_STATUSES = (126, 127)

# `sh` exits 2, the app-critical status, on a script it cannot open (a
# severed bind mount, say), so the script is checked before sh is given it.
_SMOKE_COMMAND = r"""
s={script}
[ -f "$s" ] || {{ echo "smoke script $s is not in the container" >&2; exit 127; }}
[ -r "$s" ] || {{ echo "smoke script $s is not readable by the container's user" >&2; exit 126; }}
echo {started}
exec sh "$s" {service}
"""


def smoke_command(script: str, service: str) -> str:
    """The sh command that runs a service's smoke script in its container:
    STARTED on stdout and then ``sh <script> <service>``, or neither when
    the script is missing or unreadable (sh reads it, so it needs no
    execute bit)."""
    return _SMOKE_COMMAND.format(script=shlex.quote(script), service=shlex.quote(service),
                                 started=STARTED)


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


def interpret_smoke_result(exit_code: int, stdout: str, stderr: str) -> SmokeResult:
    """Interpret what smoke_command's run exited with and wrote.

    A failure without STARTED is docker's, or a script that was not there
    to run: never the app's verdict, whatever the status."""
    if exit_code == 0:
        return SmokeResult(status="ok", message="")
    message = parse_smoke_stderr(stderr)
    if stdout.split("\n", 1)[0] != STARTED:
        return cannot_run(message)
    if exit_code == 2:
        return SmokeResult(status="critical", message=message)
    if exit_code in COMMAND_NOT_RUN_STATUSES:
        message = (f"smoke script ran and exited {exit_code}, as a shell does for a command "
                   f"that is not found or cannot be run: {message}")
    return SmokeResult(status="warning", message=message)
