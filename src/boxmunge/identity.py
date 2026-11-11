"""Project identity — ULID collision detection."""
from __future__ import annotations
from typing import TYPE_CHECKING
from boxmunge.state import read_state, write_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def check_project_identity(project_name: str, manifest_id: str, paths: BoxPaths) -> None:
    if not manifest_id:
        return
    state = read_state(paths.project_deploy_state(project_name))
    stored_id = state.get("project_id", "")
    if stored_id and stored_id != manifest_id:
        raise ValueError(
            f"Project name '{project_name}' is already registered with a "
            f"different ID ({stored_id}). Use a different name or verify "
            f"you have the correct manifest."
        )

    # Check reverse: is this ULID already used by a different project?
    if paths.deploy_state.exists():
        for state_file in paths.deploy_state.iterdir():
            other_name = state_file.stem
            # Only deploy records, `<project>.json`, hold a project_id; a
            # project name has no dot, its pause, quarantine, users and binds
            # records do, and one of those that cannot be read must not fail
            # another project's check.
            if state_file.suffix != ".json" or "." in other_name:
                continue
            if other_name == project_name:
                continue
            other_state = read_state(state_file)
            if other_state.get("project_id") == manifest_id:
                raise ValueError(
                    f"ULID '{manifest_id}' is already registered to project "
                    f"'{other_name}'. Each project must have a unique ID."
                )


def register_project_identity(project_name: str, manifest_id: str, paths: BoxPaths) -> None:
    if not manifest_id:
        return
    state_path = paths.project_deploy_state(project_name)
    state = read_state(state_path)
    state["project_id"] = manifest_id
    write_state(state_path, state)
