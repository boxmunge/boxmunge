# SPDX-License-Identifier: Apache-2.0
"""Action definitions, grouped by family, and the default registry."""
from __future__ import annotations

from boxmunge.api.actions import backups, jobs, logs, project, security, status
from boxmunge.api.registry import Registry

FAMILIES = (status, project, logs, security, backups, jobs)


def build_registry() -> Registry:
    """A registry holding every action of every family."""
    registry = Registry()
    for family in FAMILIES:
        for action in family.ACTIONS:
            registry.register(action)
    return registry
