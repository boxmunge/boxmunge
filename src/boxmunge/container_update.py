# SPDX-License-Identifier: Apache-2.0
"""Container auto-update — pull, recreate, healthcheck, and rollback for image: services.

This module is invoked by `boxmunge container-update` (CLI) on a daily timer.
For each enrolled target (Caddy + opt-in user projects), it captures the
current image digest, pulls, recreates, and waits for healthcheck. On failure
it applies the configured strategy (leave_broken or rollback_to_previous).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.manifest import load_manifest, ManifestError

if TYPE_CHECKING:
    from pathlib import Path
    from boxmunge.paths import BoxPaths


VALID_STRATEGIES = {"leave_broken", "rollback_to_previous"}


@dataclass
class UpdateTarget:
    """A single target for container update — Caddy or a user project."""
    name: str
    project_dir: "Path"
    compose_files: list[str]
    strategy: str
    has_backup: bool
    is_caddy: bool = False


def resolve_strategy(box: dict[str, Any], project: dict[str, Any] | None) -> str:
    """Resolve effective strategy: project override wins over box default."""
    if project and "strategy" in project:
        return project["strategy"]
    return box.get("strategy", "leave_broken")


def _build_caddy_target(paths: "BoxPaths", box_cu: dict[str, Any]) -> UpdateTarget:
    return UpdateTarget(
        name="caddy",
        project_dir=paths.caddy,
        compose_files=["compose.yml"],
        strategy=resolve_strategy(box_cu, project=None),
        has_backup=False,
        is_caddy=True,
    )


def _build_project_target(
    paths: "BoxPaths", box_cu: dict[str, Any], project_dir: "Path"
) -> UpdateTarget | None:
    """Build a target for a user project, or None if it should be skipped."""
    manifest_path = project_dir / "manifest.yml"
    if not manifest_path.exists():
        return None
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError:
        return None

    proj_cu = manifest.get("container_updates", {})
    if proj_cu.get("enabled") is False:
        return None

    name = manifest.get("project", project_dir.name)
    compose_files = ["compose.yml"]
    override = paths.project_compose_override(name)
    if override.exists():
        compose_files.append("compose.boxmunge.yml")

    has_backup = bool(manifest.get("backup", {}).get("dump_command"))

    return UpdateTarget(
        name=name,
        project_dir=project_dir,
        compose_files=compose_files,
        strategy=resolve_strategy(box_cu, proj_cu),
        has_backup=has_backup,
    )


def build_targets(paths: "BoxPaths", config: dict[str, Any]) -> list[UpdateTarget]:
    """Build the ordered list of update targets: Caddy first, then projects.

    Returns an empty list if container_updates.enabled is False at the box level.
    """
    box_cu = config.get("container_updates", {})
    if not box_cu.get("enabled", True):
        return []

    targets: list[UpdateTarget] = [_build_caddy_target(paths, box_cu)]

    if paths.projects.exists():
        for project_dir in sorted(paths.projects.iterdir()):
            if not project_dir.is_dir():
                continue
            target = _build_project_target(paths, box_cu, project_dir)
            if target is not None:
                targets.append(target)

    return targets


def read_target_state(paths: "BoxPaths", name: str) -> dict[str, Any] | None:
    """Read the state file for a target, or None if missing."""
    state_path = paths.container_update_target_state(name)
    if not state_path.exists():
        return None
    try:
        return json.loads(state_path.read_text())
    except json.JSONDecodeError:
        return None


def write_target_state(paths: "BoxPaths", name: str, state: dict[str, Any]) -> None:
    """Write the state file for a target atomically."""
    paths.container_update_state.mkdir(parents=True, exist_ok=True)
    state_path = paths.container_update_target_state(name)
    atomic_write_text(state_path, json.dumps(state, indent=2) + "\n")
