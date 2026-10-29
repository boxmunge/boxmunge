# SPDX-License-Identifier: Apache-2.0
"""Health check: registry entries left behind by an unfinished removal."""

from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.project_registry import (
    forget_advice, missing_among, read_registry, unfinished_removals,
)

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def check_registry_drift(paths: BoxPaths) -> HealthCheck:
    """Warn for each registered name left behind by an unfinished removal
    (no project directory, but deploy, scan or health state). A name never
    deployed is just awaiting its first deploy: ok."""
    names = read_registry(paths).names
    unfinished = unfinished_removals(names, paths)
    if unfinished:
        return HealthCheck(name="registry", status="warn",
                           detail="; ".join(forget_advice(n) for n in unfinished))
    awaiting = missing_among(names, paths)
    detail = (f"awaiting first deploy: {', '.join(awaiting)}" if awaiting
              else "every registered project has a directory")
    return HealthCheck(name="registry", status="ok", detail=detail)
