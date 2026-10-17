# SPDX-License-Identifier: Apache-2.0
"""Stages left by boxmunge 0.10.1, in the old layout (staged release in the
project dir, production's kept in .releases/prestage/).

This is the only module that knows the old layout. The upgrade never
migrates such a stage (D9): the project keeps running its current
containers, every production start or deploy for it is refused, and the
operator resolves it with `boxmunge-server legacy-stage <p>` once a
platform rollback is no longer possible. Delete this module (with the
reserved BOXMUNGE_ENTRIES / CONTROL_ENTRIES names) in the first minor whose
upgrade floor is the beta.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

LEGACY_STAGING_FILES = ("compose.staging-base.yml", "compose.boxmunge-staging.yml")


@dataclass(frozen=True)
class LegacyStage:
    kind: str   # "bundle" | "git" | "leftover"


def legacy_staging_state(paths: BoxPaths, project: str) -> Path:
    return paths.state / "staging" / f"{project}.json"


def _present(path: Path) -> bool:
    """Whether anything (a dangling link included) is at ``path``. Unlike
    os.path.lexists, an error other than absence (EACCES) is raised: it
    must not read as "no stage"."""
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    return True


def _state_active(paths: BoxPaths, project: str) -> bool:
    path = legacy_staging_state(paths, project)
    if not _present(path):
        return False
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        doc = None
    if not isinstance(doc, dict):
        return True  # unreadable: treat as a stage; legacy-stage shows the evidence
    return bool(doc.get("active"))


def legacy_stage(paths: BoxPaths, project: str) -> LegacyStage | None:
    """Read-only detection (spec 'Migration', Detection table). Raises
    OSError when it cannot tell (legacy_stage_refusal maps that)."""
    project_dir = paths.project_dir(project)
    if _present(project_dir / ".releases" / "prestage"):
        return LegacyStage("bundle")
    staged = _state_active(paths, project) or any(
        _present(project_dir / name) for name in LEGACY_STAGING_FILES)
    if not staged:
        return None
    return LegacyStage("git" if _present(project_dir / "repo") else "leftover")


def legacy_refusal(project: str, stage: LegacyStage) -> str:
    return (f"'{project}' has a release staged by boxmunge 0.10.1 ({stage.kind}); the "
            f"project directory may hold the staged files. Resolve it first with: "
            f"boxmunge-server legacy-stage {project}")


def legacy_stage_refusal(paths: BoxPaths, project: str) -> str | None:
    """Why ``project`` is refused for a 0.10.1 stage, or None. A detection
    that cannot tell refuses too."""
    try:
        stage = legacy_stage(paths, project)
    except OSError as e:
        return f"cannot tell whether a 0.10.1 stage is on disk for '{project}': {e}"
    return None if stage is None else legacy_refusal(project, stage)


def refuse_if_legacy_stage(paths: BoxPaths, project: str) -> bool:
    refusal = legacy_stage_refusal(paths, project)
    if refusal is not None:
        print(f"ERROR: {refusal}", file=sys.stderr)
    return refusal is not None
