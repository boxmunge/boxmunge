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
means for production (a bind gets the ``-staging`` suffix). A build
context in box state is refused: staging would build from other files
than production. Explicit volume and network names and published ports
are dropped (container_name never gets here: validation refuses it);
staging_isolation then proves the result disjoint.
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


def _staging_read_file(entry: Any, project_dir: Path, box_state: set[str]) -> Any:
    """An env_file or label_file entry: Compose reads the file, nothing mounts it."""
    if isinstance(entry, str):
        return staging_source(entry, project_dir, box_state, bind=False)
    if isinstance(entry, dict) and isinstance(entry.get("path"), str):
        return {**entry, "path": staging_source(entry["path"], project_dir, box_state, bind=False)}
    return entry


def _build_input(path: str, project_dir: Path, box_state: set[str], what: str) -> str:
    """A local build input stays relative unless it leaves the project.
    One in box state is refused: staging would build from release/'s copy
    of the name while production builds from the data itself."""
    if "://" in path:
        return path
    rel = project_relative(path, project_dir)
    if rel is None:
        return path if os.path.isabs(path) or path.startswith("~") \
            else os.path.normpath(os.path.join(project_dir, path))
    top = rel.partition(os.sep)[0]
    if top in box_state:
        raise ComposeError(
            f"build {what} {path!r} is in {top}, which the project dir keeps as "
            f"server-owned state, not release code, so staging and production "
            f"would build from different files. Build from release code: move "
            f"the build inputs into a directory the release carries.")
    return path


def _staging_contexts(contexts: Any, project_dir: Path, box_state: set[str]) -> Any:
    def one(name: str, ref: str) -> str:
        return _build_input(ref, project_dir, box_state, f"additional_contexts.{name}")
    if isinstance(contexts, dict):
        return {k: one(k, v) if isinstance(v, str) else v for k, v in contexts.items()}
    if not isinstance(contexts, list):
        return contexts
    out = []
    for entry in contexts:
        name, sep, ref = entry.partition("=") if isinstance(entry, str) else ("", "", "")
        out.append(f"{name}={one(name, ref)}" if sep else entry)
    return out


def _staging_build(build: Any, project_dir: Path, box_state: set[str]) -> Any:
    if isinstance(build, str):
        return _build_input(build, project_dir, box_state, "context")
    if not isinstance(build, dict):
        return build
    build = dict(build)
    if isinstance(build.get("context"), str):
        build["context"] = _build_input(build["context"], project_dir, box_state, "context")
    if "additional_contexts" in build:
        build["additional_contexts"] = _staging_contexts(
            build["additional_contexts"], project_dir, box_state)
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
        volumes = svc.get("volumes")
        if isinstance(volumes, list):
            svc["volumes"] = [_staging_volume(v, project_dir, box_state) for v in volumes]
        for key in ("env_file", "label_file"):
            if svc.get(key) is not None:
                entries = svc[key] if isinstance(svc[key], list) else [svc[key]]
                svc[key] = [_staging_read_file(e, project_dir, box_state) for e in entries]
        if "build" in svc:
            svc["build"] = _staging_build(svc["build"], project_dir, box_state)
    return yaml.dump(doc, default_flow_style=False, sort_keys=False)
