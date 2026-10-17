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


def _state_active(paths: BoxPaths, project: str) -> bool:
    path = legacy_staging_state(paths, project)
    if not path.exists():
        return False
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        doc = None
    if not isinstance(doc, dict):
        return True  # unreadable: treat as a stage; legacy-stage shows the evidence
    return bool(doc.get("active"))


def legacy_stage(paths: BoxPaths, project: str) -> LegacyStage | None:
    """Read-only detection (spec 'Migration', Detection table)."""
    project_dir = paths.project_dir(project)
    if os.path.lexists(project_dir / ".releases" / "prestage"):
        return LegacyStage("bundle")
    staged = _state_active(paths, project) or any(
        os.path.lexists(project_dir / name) for name in LEGACY_STAGING_FILES)
    if not staged:
        return None
    return LegacyStage("git" if (project_dir / "repo").exists() else "leftover")


def legacy_refusal(project: str, stage: LegacyStage) -> str:
    return (f"'{project}' has a release staged by boxmunge 0.10.1 ({stage.kind}); the "
            f"project directory may hold the staged files. Resolve it first with: "
            f"boxmunge-server legacy-stage {project}")


def refuse_if_legacy_stage(paths: BoxPaths, project: str) -> bool:
    stage = legacy_stage(paths, project)
    if stage is not None:
        print(f"ERROR: {legacy_refusal(project, stage)}", file=sys.stderr)
    return stage is not None
