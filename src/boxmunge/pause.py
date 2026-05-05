# SPDX-License-Identifier: Apache-2.0
"""Pause-state primitives for projects.

A project is "paused" iff state/deploy/<project>.paused.json exists.
This file is the single source of truth for pause state — deploy.json
is never extended with a paused field.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths


def is_paused(project_name: str, paths: BoxPaths) -> bool:
    """True if the project has been paused."""
    return paths.project_paused_state(project_name).exists()


def write_paused_state(
    project_name: str, paths: BoxPaths, reason: str | None = None,
) -> None:
    """Mark the project as paused. Records UTC timestamp; reason optional."""
    data: dict[str, Any] = {
        "paused_at": datetime.now(timezone.utc).isoformat(),
    }
    if reason is not None:
        data["reason"] = reason
    paths.project_paused_state(project_name).parent.mkdir(
        parents=True, exist_ok=True,
    )
    atomic_write_text(
        paths.project_paused_state(project_name),
        json.dumps(data, indent=2) + "\n",
    )


def clear_paused_state(project_name: str, paths: BoxPaths) -> None:
    """Mark the project as no longer paused. Idempotent."""
    paths.project_paused_state(project_name).unlink(missing_ok=True)


def read_paused_state(
    project_name: str, paths: BoxPaths,
) -> dict[str, Any] | None:
    """Return the paused.json contents, or None if not paused."""
    path = paths.project_paused_state(project_name)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def render_maintenance_caddy_config(hosts: list[str]) -> str:
    """Generate a Caddyfile fragment that serves the maintenance page.

    Issues HTTP 503 with a Retry-After header, serving the static HTML
    out of /etc/caddy/maintenance (mounted from
    /opt/boxmunge/caddy/maintenance on the host).
    """
    if not hosts:
        raise ValueError("Maintenance config requires at least one host")
    host_block = ", ".join(hosts)
    return (
        f"{host_block} {{\n"
        f"  handle {{\n"
        f"    header Retry-After 3600\n"
        f"    root * /etc/caddy/maintenance\n"
        f"    file_server\n"
        f"    respond 503\n"
        f"  }}\n"
        f"}}\n"
    )
