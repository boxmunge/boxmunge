# SPDX-License-Identifier: Apache-2.0
"""Pieces the action families share: parameter schemas and project lookup."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import BOOLEAN, STRING, obj
from boxmunge.cve.quarantine import QUARANTINE_TEXT_FIELDS, checked_quarantine_record
from boxmunge.paths import BoxPaths, InvalidProjectName

PROJECT_NAME_PATTERN = "[a-z0-9][a-z0-9-]{0,62}"
PROJECT_PARAM: dict[str, Any] = {
    "type": "string", "pattern": PROJECT_NAME_PATTERN,
    "description": "Project name, as projects.list returns it.",
}
NO_PARAMS = obj({})
TAIL_MAX = 1000

QUARANTINE_SCHEMA = obj({
    "quarantined_at": STRING,
    "cve_id": STRING,
    "severity": STRING,
    "effective_severity": STRING,
    "explanation": STRING,
    "image_ref": STRING,
    "action_complete": BOOLEAN,
})


def existing_project(paths: BoxPaths, name: str) -> Path:
    """The project's directory. A reserved or invalid name is invalid_params;
    a project that does not exist is not_found."""
    try:
        project_dir = paths.project_dir(name)
    except InvalidProjectName as e:
        raise ActionError(ErrorCode.INVALID_PARAMS, str(e)) from e
    if not project_dir.is_dir():
        raise ActionError(ErrorCode.NOT_FOUND,
                          f"Project not found: {name}. projects.list names the projects "
                          f"on this box.")
    return project_dir


def deployed_project(paths: BoxPaths, name: str) -> Path:
    """As existing_project, and the project must have been deployed."""
    project_dir = existing_project(paths, name)
    if not (project_dir / "manifest.yml").exists():
        raise ActionError(ErrorCode.CONFLICT,
                          f"Project '{name}' is registered but not yet deployed.")
    return project_dir


def quarantine_view(state: dict[str, Any] | None, path: Path) -> dict[str, Any]:
    """The quarantine state file at *path* as QUARANTINE_SCHEMA describes it.
    A record without action_complete predates it and counts as incomplete;
    any other departure from what boxmunge writes is QuarantineError."""
    record = checked_quarantine_record(state, path)
    return {
        **{key: record[key] for key in QUARANTINE_TEXT_FIELDS},
        "action_complete": record.get("action_complete", False),
    }
