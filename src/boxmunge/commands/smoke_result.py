# SPDX-License-Identifier: Apache-2.0
"""What a smoke test's exit code and stderr mean, per the boxmunge contract.

Pure interpretation, split from commands.check, which runs the smoke
scripts inside the containers.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SmokeResult:
    status: str  # "ok", "warning", "critical"
    message: str


def parse_smoke_stderr(stderr: str) -> str:
    """Parse smoke test stderr according to the boxmunge contract."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]

    if not lines:
        return "Smoke check failed (no detail provided)"
    if len(lines) == 1:
        return lines[0]
    return "Manual failure analysis required (smoke script produced multiple lines)"


# Stderr signatures that mean the smoke test could not be RUN — the container
# is gone/renamed/not running, or `sh` could not open the script — as opposed
# to the app's smoke test running and reporting a problem. These are harness /
# infrastructure failures: they carry no signal about app health, so they must
# never escalate to CRITICAL (which stops+removes the container via the health
# monitor). Note `sh` exits 2 when it cannot open a script — colliding with the
# app-critical exit code — so exit code alone cannot distinguish them.
_HARNESS_FAILURE_SIGNATURES = (
    "no such container",
    "is not running",
    "is restarting",
    "cannot open",
    "can't open",
    "exec failed",
    "executable file not found",
    "oci runtime",
)


def _is_harness_failure(stderr: str) -> bool:
    """True if stderr indicates the smoke could not be run (not app-critical)."""
    low = stderr.lower()
    return any(sig in low for sig in _HARNESS_FAILURE_SIGNATURES)


def interpret_smoke_result(exit_code: int, stderr: str) -> SmokeResult:
    """Interpret a smoke test exit code and stderr into a SmokeResult."""
    message = parse_smoke_stderr(stderr)

    if exit_code == 0:
        return SmokeResult(status="ok", message="")
    # A failure whose stderr shows the smoke could not even run (container
    # gone, script unopenable) is downgraded to WARNING regardless of exit
    # code: it is an infrastructure fault, not evidence the app is unhealthy,
    # and must not trip the CRITICAL -> compose_down path that takes prod
    # offline. Surfaced (not silenced) so the operator still gets an alert.
    if exit_code != 0 and _is_harness_failure(stderr):
        return SmokeResult(
            status="warning",
            message=f"smoke could not run (infrastructure, not app): {message}",
        )
    if exit_code == 2:
        return SmokeResult(status="critical", message=message)
    else:
        return SmokeResult(status="warning", message=message)
