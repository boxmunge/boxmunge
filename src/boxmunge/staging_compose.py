# SPDX-License-Identifier: Apache-2.0
"""The staging compose base: compose.yml rewritten so staging shares nothing
with production.

Staging runs from the project directory beside production, as compose
project ``<project>-staging``. Compose namespaces what it names itself
(containers, default-named volumes and networks) by project, but not what
compose.yml names explicitly, and a bind mount names a host path. So the
base drops every explicit name (validation allows only the project's own,
which is what Compose would choose anyway), drops published ports, and
points each bind mount and config or secret file in box state (data
directories, secrets.env, ...) at the entry's ``-staging`` copy:
``./uploads/img`` becomes ``./uploads-staging/img``. Mounts of release code keep their source, so
staging reads the staged release installed in the project dir; production
reads its own copy (see live_mounts). A source outside the project gets a
``-staging`` suffix. stage_isolation then proves the result disjoint.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from boxmunge.bind_mounts import project_relative
from boxmunge.compose import ComposeError
from boxmunge.compose_mounts import is_bind_entry, volume_source

STAGING_BASE = "compose.staging-base.yml"
STAGING_OVERLAY = "compose.boxmunge-staging.yml"
STAGING_FILES = [STAGING_BASE, STAGING_OVERLAY]


def staging_source(source: str, project_dir: Path, box_state: set[str]) -> str:
    """Where staging mounts what production mounts from ``source``."""
    rel = project_relative(source, project_dir)
    if rel is None:
        return source.rstrip("/") + "-staging"
    if rel == ".":
        return source  # the isolation check refuses it, naming the mount
    top, _, rest = rel.partition(os.sep)
    if top not in box_state:
        return source
    return "./" + "/".join(p for p in (f"{top}-staging", rest) if p)


def _staging_volume(entry: Any, project_dir: Path, box_state: set[str]) -> Any:
    if not is_bind_entry(entry):
        return entry
    new = staging_source(volume_source(entry), project_dir, box_state)
    if isinstance(entry, dict):
        return {**entry, "source": new}
    return ":".join([new, *entry.split(":")[1:]])


def _drop_names(doc: dict[str, Any], kind: str) -> None:
    decls = doc.get(kind)
    if not isinstance(decls, dict):
        return
    for key, decl in decls.items():
        if not isinstance(decl, dict):
            continue
        if decl.get("external"):
            raise ComposeError(f"top-level {kind[:-1]} {key!r} is external; "
                               f"staging would share it with production")
        decl.pop("name", None)


def generate_staging_compose_base(compose_path: Path, box_state: set[str],
                                  project_dir: Path | None = None) -> str:
    """Return compose.yml rewritten for staging (see module docstring).

    ``box_state`` names the project entries that are not release code;
    ``project_dir`` is where the release is (or will be) installed, by
    default the compose file's directory.
    Services pulled in by `include:` or `extends: {file: ...}` live in
    other files this rewrite cannot reach, so those are refused rather
    than staged with production's mounts.
    """
    doc = yaml.safe_load(Path(compose_path).read_text())
    if not isinstance(doc, dict):
        raise ComposeError(
            f"compose.yml must be a YAML mapping at the top level "
            f"(got {type(doc).__name__})"
        )
    services = doc.get("services")
    if services is not None and not isinstance(services, dict):
        raise ComposeError(
            f"compose.yml 'services' must be a mapping "
            f"(got {type(services).__name__})"
        )
    other_files = "include" in doc or any(
        isinstance(svc, dict) and isinstance(svc.get("extends"), dict)
        and "file" in svc["extends"] for svc in (services or {}).values()
    )
    if other_files:
        raise ComposeError(
            "stage cannot separate staging from production for services that "
            "come from include: or extends: file: (their bind mounts would be "
            "shared with production). Move those services into compose.yml to "
            "use stage."
        )
    project_dir = project_dir or Path(compose_path).parent
    _drop_names(doc, "volumes")
    _drop_names(doc, "networks")
    for section in ("configs", "secrets"):
        decls = doc.get(section)
        for decl in (decls.values() if isinstance(decls, dict) else []):
            if isinstance(decl, dict) and isinstance(decl.get("file"), str):
                decl["file"] = staging_source(decl["file"], project_dir, box_state)
    for svc in (services or {}).values():
        if not isinstance(svc, dict):
            continue  # malformed entry: leave it for Compose to reject
        svc.pop("ports", None)
        svc.pop("container_name", None)
        volumes = svc.get("volumes")
        if isinstance(volumes, list):
            svc["volumes"] = [_staging_volume(v, project_dir, box_state) for v in volumes]
    return yaml.dump(doc, default_flow_style=False, sort_keys=False)
