# SPDX-License-Identifier: Apache-2.0
"""What a handler receives besides its parameters.

Handlers read state files through ctx.paths. Facts that need Docker or the
host (health probes, smoke checks, container logs) come through ctx.host, a
HostProbe: LiveHost on a real box, FixtureHost in dev mode. ctx.emit is set
only for actions that run as jobs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from boxmunge.api.principal import Principal
from boxmunge.paths import BoxPaths


class HostProbe(Protocol):
    def health_report(self) -> dict[str, Any]:
        """The platform health report, shaped like `health --json`."""

    def project_check(self, project: str) -> dict[str, Any]:
        """One project's smoke check, shaped like `check <project> --json`."""

    def container_logs(self, project: str, service: str | None, tail: int) -> str:
        """The last *tail* lines of the project's container logs."""


Emit = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class ActionContext:
    principal: Principal
    paths: BoxPaths
    host: HostProbe
    emit: Emit | None = None
