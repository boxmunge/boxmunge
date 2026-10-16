# SPDX-License-Identifier: Apache-2.0
"""Put a test project in the state a deploy leaves it in."""
from __future__ import annotations

import yaml

from boxmunge import compose_resolve
from boxmunge.bind_sources import model_sources, record
from boxmunge.paths import BoxPaths


def mark_deployed(paths: BoxPaths, name: str) -> None:
    """Record the project's bind sources and control-file hashes, as a
    deploy does, so the start checks of resume, recover, restore and the
    timers accept it."""
    project_dir = paths.project_dir(name)
    model = yaml.safe_load((project_dir / "compose.yml").read_text()) or {}
    _, read_files = compose_resolve.walk_references(project_dir / "compose.yml", (project_dir,))
    record(project_dir, model_sources(model, project_dir), read_files,
           paths.project_bind_record(name))
