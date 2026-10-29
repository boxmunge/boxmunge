# SPDX-License-Identifier: Apache-2.0
"""Health check: registry entries with no project directory."""

from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.project_registry import forget_advice, missing_among, read_registry

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def check_registry_drift(paths: BoxPaths) -> HealthCheck:
    """Warn for each registered project name with no project directory: a
    removal that did not finish, or a project-add not yet deployed. Nothing
    can be scanned or checked for it, and it should not look like a failure."""
    missing = missing_among(read_registry(paths).names, paths)
    if missing:
        return HealthCheck(name="registry", status="warn",
                           detail="; ".join(forget_advice(n) for n in missing))
    return HealthCheck(name="registry", status="ok",
                       detail="every registered project has a directory")
