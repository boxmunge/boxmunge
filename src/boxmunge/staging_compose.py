# SPDX-License-Identifier: Apache-2.0
"""The staging compose base: the staged release's compose.yml rewritten so
staging shares nothing with production.

Staging runs from the slot with ``--project-directory <slot>/release``, so
a relative path resolves inside the staged release exactly as it will in
the project dir once promoted. Release-code paths therefore stay relative.
What production keeps as box state (data directories, secrets.env, ...)
is pointed at by absolute path: bind mounts and config/secret files at
the entry's ``-staging`` copy in the project dir, env files at the file
itself (Compose reads them; nothing is mounted). A path that leaves the
project is made absolute against the project dir, so it means what it
means for production (a bind gets the ``-staging`` suffix). Explicit
names and published ports are dropped; staging_isolation then proves the
result disjoint.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from boxmunge.bind_mounts import project_relative
from boxmunge.compose import ComposeError
from boxmunge.compose_mounts import is_bind_entry, volume_source
from boxmunge.staged_release import STAGING_BASE, STAGING_OVERLAY

STAGING_FILES = [STAGING_BASE, STAGING_OVERLAY]


def staging_source(source: str, project_dir: Path, box_state: set[str], *, bind: bool) -> str:
    """Where staging reads what production reads from ``source``. A bind
    (or config/secret file, which Compose mounts) gets staging's copy; an
    env file, read by Compose and never mounted, is the file itself."""
    rel = project_relative(source, project_dir)
    if rel is None:
        outside = source if os.path.isabs(source) or source.startswith("~") \
            else os.path.normpath(os.path.join(project_dir, source))
        return outside.rstrip("/") + ("-staging" if bind else "")
    if rel == ".":
        return source  # the isolation check refuses it, naming the mount
    top, _, rest = rel.partition(os.sep)
    if top not in box_state:
        return source
    if not bind:
        return str(project_dir / rel)
    return str(project_dir / f"{top}-staging" / rest) if rest else str(project_dir / f"{top}-staging")


def _staging_volume(entry: Any, project_dir: Path, box_state: set[str]) -> Any:
    if not is_bind_entry(entry):
        return entry
    new = staging_source(volume_source(entry), project_dir, box_state, bind=True)
    if isinstance(entry, dict):
        return {**entry, "source": new}
    return ":".join([new, *entry.split(":")[1:]])


def _staging_env_file(entry: Any, project_dir: Path, box_state: set[str]) -> Any:
    if isinstance(entry, str):
        return staging_source(entry, project_dir, box_state, bind=False)
    if isinstance(entry, dict) and isinstance(entry.get("path"), str):
        return {**entry, "path": staging_source(entry["path"], project_dir, box_state, bind=False)}
    return entry


def _outside_only(path: str, project_dir: Path) -> str:
    """Build inputs stay relative unless they leave the project."""
    if os.path.isabs(path) or "://" in path or project_relative(path, project_dir) is not None:
        return path
    return os.path.normpath(os.path.join(project_dir, path))


def _staging_build(build: Any, project_dir: Path) -> Any:
    if isinstance(build, str):
        return _outside_only(build, project_dir)
    if isinstance(build, dict) and isinstance(build.get("context"), str):
        return {**build, "context": _outside_only(build["context"], project_dir)}
    return build


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
                                  project_dir: Path) -> str:
    """Return the staged compose.yml rewritten for staging (module docstring).

    ``project_dir`` is production's project dir; ``box_state`` its entries
    that are not release code (data_dirs).
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
    _drop_names(doc, "volumes")
    _drop_names(doc, "networks")
    for section in ("configs", "secrets"):
        decls = doc.get(section)
        for decl in (decls.values() if isinstance(decls, dict) else []):
            if isinstance(decl, dict) and isinstance(decl.get("file"), str):
                decl["file"] = staging_source(decl["file"], project_dir, box_state, bind=True)
    for svc in (services or {}).values():
        if not isinstance(svc, dict):
            continue  # malformed entry: leave it for Compose to reject
        svc.pop("ports", None)
        svc.pop("container_name", None)
        volumes = svc.get("volumes")
        if isinstance(volumes, list):
            svc["volumes"] = [_staging_volume(v, project_dir, box_state) for v in volumes]
        env = svc.get("env_file")
        if env is not None:
            entries = env if isinstance(env, list) else [env]
            svc["env_file"] = [_staging_env_file(e, project_dir, box_state) for e in entries]
        if "build" in svc:
            svc["build"] = _staging_build(svc["build"], project_dir)
    return yaml.dump(doc, default_flow_style=False, sort_keys=False)
