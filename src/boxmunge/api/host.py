# SPDX-License-Identifier: Apache-2.0
"""LiveHost: the HostProbe for a real box, backed by the CLI's own probes."""
from __future__ import annotations

from typing import Any

from boxmunge.paths import BoxPaths


class LiveHost:
    def __init__(self, paths: BoxPaths) -> None:
        self._paths = paths

    def health_report(self) -> dict[str, Any]:
        from boxmunge.commands.health_cmd import collect_health
        return collect_health(self._paths).to_dict()

    def project_check(self, project: str) -> dict[str, Any]:
        from boxmunge.commands.check import collect_check
        return collect_check(project, self._paths)

    def container_logs(self, project: str, service: str | None, tail: int) -> str:
        """Raises DockerError when docker compose cannot read the logs."""
        from boxmunge.docker import compose_logs_capture
        compose_files = ["compose.yml"]
        if self._paths.project_compose_override(project).exists():
            compose_files.append("compose.boxmunge.yml")
        return compose_logs_capture(
            self._paths.project_dir(project), service=service, tail=tail,
            compose_files=compose_files, project_name=project,
        )
