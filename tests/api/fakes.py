# SPDX-License-Identifier: Apache-2.0
"""Test doubles and helpers shared by the action API tests."""
from __future__ import annotations

import json
from typing import Any

from boxmunge.api.audit import AuditLog
from boxmunge.api.invoke import ALL_TIERS, Invoker
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Registry
from boxmunge.paths import BoxPaths


class StubHost:
    """A HostProbe with canned answers; records the log requests it gets."""

    def __init__(self, *, health: dict[str, Any] | None = None,
                 checks: dict[str, dict[str, Any]] | None = None,
                 logs: dict[str, Any] | None = None) -> None:
        self.health = health or {"healthy": True, "exit_code": 0, "checks": []}
        self.checks = checks or {}
        self.logs = logs or {}
        self.log_calls: list[tuple[str, str | None, int]] = []

    def health_report(self) -> dict[str, Any]:
        return self.health

    def project_check(self, project: str) -> dict[str, Any]:
        return self.checks[project]

    def container_logs(self, project: str, service: str | None, tail: int) -> str:
        self.log_calls.append((project, service, tail))
        answer = self.logs[project]
        if isinstance(answer, Exception):
            raise answer
        return answer


def make_invoker(paths: BoxPaths, *, registry: Registry | None = None,
                 host: Any = None, served_tiers: frozenset[Tier] = ALL_TIERS) -> Invoker:
    """An Invoker over *paths*; the full registry unless one is given."""
    if registry is None:
        from boxmunge.api.actions import build_registry
        registry = build_registry()
    return Invoker(registry, paths, host or StubHost(), AuditLog(paths.audit_log),
                   served_tiers=served_tiers)


def read_audit(paths: BoxPaths) -> list[dict[str, Any]]:
    if not paths.audit_log.exists():
        return []
    return [json.loads(line) for line in paths.audit_log.read_text().splitlines()]
