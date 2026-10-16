# SPDX-License-Identifier: Apache-2.0
"""HostProbe for a fixture box: canned Docker and host answers from <root>/dev/."""
from __future__ import annotations

import json
from typing import Any

from boxmunge.api.dev.fixture_projects import DEV_DIR
from boxmunge.paths import BoxPaths


class FixtureHost:
    def __init__(self, paths: BoxPaths) -> None:
        self._dev = paths.root / DEV_DIR

    def health_report(self) -> dict[str, Any]:
        return json.loads((self._dev / "health.json").read_text())

    def project_check(self, project: str) -> dict[str, Any]:
        return json.loads((self._dev / "checks" / f"{project}.json").read_text())

    def container_logs(self, project: str, service: str | None, tail: int) -> str:
        project_logs = self._dev / "logs" / project
        files = ([project_logs / f"{service}.log"] if service is not None
                 else sorted(project_logs.glob("*.log")))
        lines = [line for path in files for line in path.read_text().splitlines()]
        return "".join(f"{line}\n" for line in lines[-tail:])
