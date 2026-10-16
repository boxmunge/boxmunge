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

from boxmunge import restart_hold
from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths
from boxmunge.state import read_state


def is_paused(project_name: str, paths: BoxPaths) -> bool:
    """True if the project has been paused."""
    return paths.project_paused_state(project_name).exists()


def write_paused_state(
    project_name: str, paths: BoxPaths, reason: str | None = None,
) -> None:
    """Mark the project as paused. Records UTC timestamp; reason optional.

    The record says ``action_complete: false`` until mark_pause_complete:
    the maintenance page, the stop and the restart-policy hold all landed.
    """
    data: dict[str, Any] = {
        "paused_at": datetime.now(timezone.utc).isoformat(),
        "action_complete": False,
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


def _update_paused_state(project_name: str, paths: BoxPaths, **fields: Any) -> None:
    state = read_paused_state(project_name, paths)
    if state is None:
        raise ValueError(f"project {project_name!r} is not paused")
    atomic_write_text(
        paths.project_paused_state(project_name),
        json.dumps({**state, **fields}, indent=2) + "\n",
    )


def pause_action_complete(project_name: str, paths: BoxPaths) -> bool:
    """True iff the pause record says every step of the pause landed. A
    record without the field is incomplete, so pausing again finishes it."""
    state = read_paused_state(project_name, paths)
    return bool(state and state.get("action_complete") is True)


def mark_pause_complete(project_name: str, paths: BoxPaths) -> None:
    _update_paused_state(project_name, paths, action_complete=True)


def hold_restart_policies(project_name: str, paths: BoxPaths) -> None:
    """Keep a paused project's containers stopped across a Docker restart.

    Sets each container's restart policy to "no" and saves the originals in
    the pause record (see boxmunge.restart_hold). Raises DockerError.
    """
    state = read_paused_state(project_name, paths) or {}
    saved = restart_hold.hold(project_name, state.get("restart_policies") or {})
    _update_paused_state(project_name, paths, restart_policies=saved)


def release_restart_policies(project_name: str, paths: BoxPaths) -> None:
    """Give a paused project's containers their saved restart policies back.
    Raises DockerError."""
    state = read_paused_state(project_name, paths) or {}
    restart_hold.release(project_name, state.get("restart_policies") or {})


def hand_over_restart_policies(
    project_name: str, paths: BoxPaths, saved: dict[str, str],
) -> None:
    """A quarantine lifted while paused passes its saved originals to the
    pause record, so the containers stay held until `resume`."""
    state = read_paused_state(project_name, paths) or {}
    merged = restart_hold.originals(state.get("restart_policies") or {}, saved)
    _update_paused_state(project_name, paths, restart_policies=merged)


def clear_paused_state(project_name: str, paths: BoxPaths) -> None:
    """Mark the project as no longer paused. Idempotent."""
    paths.project_paused_state(project_name).unlink(missing_ok=True)


def read_paused_state(
    project_name: str, paths: BoxPaths,
) -> dict[str, Any] | None:
    """Return the paused.json contents, or None if not paused.

    Raises StateError, naming the file, if it is unreadable or not a JSON
    object.
    """
    path = paths.project_paused_state(project_name)
    if not path.exists():
        return None
    return read_state(path)


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
        f"    file_server {{\n"
        f"      status 503\n"
        f"    }}\n"
        f"  }}\n"
        f"}}\n"
    )
